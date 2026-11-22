use crate::github::{execute_approved_queue_item, initialize_managed_repository, sync_bare_branch_to_github};
use crate::inspector::{
    build_git_receive_pack_rejection, compute_bare_diff_summary, evaluate_push_updates,
    parse_receive_pack_commands, PushVerdictKind, ZERO_SHA,
};
use crate::queue::{QueueItemKind, QueueItemStatus, StateStore};
use crate::vault::{AdminSecret, VaultManager};
use crate::vcs::check_vcs_tools;
use axum::{
    body::Bytes,
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

pub struct AppState {
    pub base_dir: PathBuf,
    pub port: u16,
    pub vault: VaultManager,
    pub store: StateStore,
}

const INDEX_HTML: &str = include_str!("../static/index.html");
const STYLES_CSS: &str = include_str!("../static/styles.css");
const APP_JS: &str = include_str!("../static/app.js");
const ICON_192_PNG: &[u8] = include_bytes!("../static/icon-192.png");
const ICON_512_PNG: &[u8] = include_bytes!("../static/icon-512.png");
const MANIFEST_JSON: &str = include_str!("../static/manifest.webmanifest");

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Embedded Portable Web UI & PWA Manifest
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/manifest.webmanifest", get(serve_manifest))
        .route("/favicon.ico", get(serve_icon_192))
        .route("/static/icon-192.png", get(serve_icon_192))
        .route("/static/icon-512.png", get(serve_icon_512))
        .route("/static/styles.css", get(serve_css))
        .route("/static/app.js", get(serve_js))
        // Git Smart HTTP Proxy Endpoints (`/git/:repo/info/refs`, `/git/:repo/git-upload-pack`, `/git/:repo/git-receive-pack`)
        .route("/git/:repo/info/refs", get(git_info_refs))
        .route("/git/:repo/git-upload-pack", post(git_upload_pack))
        .route("/git/:repo/git-receive-pack", post(git_receive_pack))
        // REST API for Web UI & CLI
        .route("/api/status", get(api_status))
        .route("/api/autostart", post(api_autostart))
        .route("/api/vault/setup", post(api_vault_setup))
        .route("/api/repos/check-name", get(api_check_repo_name))
        .route("/api/repos/init", post(api_repo_init))
        .route("/api/templates", get(api_templates_list).post(api_templates_save))
        .route("/api/templates/:id", axum::routing::delete(api_templates_delete))
        .route("/api/mr/create", post(api_mr_create))
        .route("/api/queue/:id/toggle", post(api_queue_toggle))
        .route("/api/queue/:id/reject", post(api_queue_reject))
        .route("/api/queue/:id/diff", get(api_queue_diff))
        .route("/api/queue/approve-batch", post(api_approve_batch))
        .with_state(state)
}

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn serve_manifest() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/manifest+json; charset=utf-8",
        )],
        MANIFEST_JSON,
    )
}

async fn serve_icon_192() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/png")],
        ICON_192_PNG,
    )
}

async fn serve_icon_512() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/png")],
        ICON_512_PNG,
    )
}

async fn serve_css() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")], STYLES_CSS)
}

async fn serve_js() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        APP_JS,
    )
}

fn clean_repo_param(raw: &str) -> String {
    raw.trim_end_matches(".git").to_string()
}

/// Validates the per-project proxy token passed by Git in `Authorization: Basic ...`
fn verify_project_token(state: &AppState, repo_name: &str, headers: &HeaderMap) -> Result<(), Response> {
    let managed = match state.store.get_repo(repo_name) {
        Some(r) => r,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("gitOlorin: Repository '{}' not registered", repo_name),
            )
                .into_response())
        }
    };

    if let Some(auth_val) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_val.to_str() {
            if let Some(b64_part) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = B64.decode(b64_part.trim()) {
                    if let Ok(creds) = String::from_utf8(decoded) {
                        if creds.ends_with(&format!(":{}", managed.project_proxy_token)) {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    // Challenge for HTTP Basic Auth if missing or wrong token
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        "gitOlorin: Per-repository proxy token required (cross-repository access denied)",
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Basic realm=\"gitOlorin Project Bastion\""),
    );
    Err(resp)
}

/// Git Smart HTTP: `GET /git/:repo/info/refs?service=git-upload-pack|git-receive-pack`
async fn git_info_refs(
    State(state): State<Arc<AppState>>,
    AxumPath(repo_param): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let repo_name = clean_repo_param(&repo_param);
    if let Err(resp) = verify_project_token(&state, &repo_name, &headers) {
        state.store.add_audit(
            &repo_name,
            "unauthorized-agent",
            "git_info_refs",
            false,
            "Intento de acceso con token de otro repositorio o sin token local.",
        );
        return resp;
    }

    let service = match params.get("service").map(|s| s.as_str()) {
        Some("git-upload-pack") => "upload-pack",
        Some("git-receive-pack") => "receive-pack",
        _ => return (StatusCode::BAD_REQUEST, "Unsupported git service").into_response(),
    };

    let bare_path = state.store.staging_dir.join(format!("{}.git", repo_name));
    if !bare_path.is_dir() {
        return (StatusCode::NOT_FOUND, "Bare staging repo not found").into_response();
    }

    let out = match Command::new("git")
        .args([service, "--stateless-rpc", "--advertise-refs"])
        .arg(&bare_path)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to run git {}: {}", service, e),
            )
                .into_response()
        }
    };

    let header_line = format!("# service=git-{}\n", service);
    let pkt_prefix = format!("{:04x}{}", header_line.len() + 4, header_line);
    let mut payload = Vec::new();
    payload.extend_from_slice(pkt_prefix.as_bytes());
    payload.extend_from_slice(b"0000");
    payload.extend_from_slice(&out.stdout);

    let content_type = format!("application/x-git-{}-advertisement", service);
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, content_type.as_str()),
            (axum::http::header::CACHE_CONTROL, "no-cache"),
        ],
        payload,
    )
        .into_response()
}

/// Git Smart HTTP: `POST /git/:repo/git-upload-pack` (`git fetch` / `git pull` / `jj git fetch`)
async fn git_upload_pack(
    State(state): State<Arc<AppState>>,
    AxumPath(repo_param): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let repo_name = clean_repo_param(&repo_param);
    if let Err(resp) = verify_project_token(&state, &repo_name, &headers) {
        return resp;
    }

    let bare_path = state.store.staging_dir.join(format!("{}.git", repo_name));
    let mut child = match Command::new("git")
        .args(["upload-pack", "--stateless-rpc"])
        .arg(&bare_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(&body);
    }

    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/x-git-upload-pack-result",
        )],
        out.stdout,
    )
        .into_response()
}

/// Git Smart HTTP: `POST /git/:repo/git-receive-pack` (`git push` / `jj git push`)
/// THIS IS THE CORE BASTION GATEKEEPER ("YOU SHALL NOT PASS!")
async fn git_receive_pack(
    State(state): State<Arc<AppState>>,
    AxumPath(repo_param): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let repo_name = clean_repo_param(&repo_param);
    if let Err(resp) = verify_project_token(&state, &repo_name, &headers) {
        return resp;
    }

    let bare_path = state.store.staging_dir.join(format!("{}.git", repo_name));
    let wcfg = state.vault.load_worker_config();

    // 1. Parse pkt-line ref update commands before touching the repository
    let updates = parse_receive_pack_commands(&body);
    let pre_eval = evaluate_push_updates(&bare_path, &updates, &wcfg.protected_branches);

    if !pre_eval.allowed {
        let first_ref = updates
            .first()
            .map(|u| u.ref_name.clone())
            .unwrap_or_else(|| "refs/heads/main".to_string());
        let old_sha = updates
            .first()
            .map(|u| u.old_sha.clone())
            .unwrap_or_else(|| ZERO_SHA.to_string());
        let new_sha = updates
            .first()
            .map(|u| u.new_sha.clone())
            .unwrap_or_else(|| ZERO_SHA.to_string());

        // If the agent pushed commits to a protected branch (e.g. main), we still want to capture
        // the packfile objects into a parked staging ref (`refs/olorin/pending/<timestamp>`) so the human
        // can inspect the diff and approve it with 1 fingerprint without the agent losing its commits!
        let mut parked_branch = first_ref.clone();
        if matches!(pre_eval.verdict, PushVerdictKind::BlockedProtectedBranch { .. })
            && new_sha != ZERO_SHA
        {
            parked_branch = format!("refs/heads/olorin-parked-{}", &new_sha[..7.min(new_sha.len())]);
            let rewritten_body = rewrite_first_ref_in_receive_pack(&body, &first_ref, &parked_branch);
            if let Some(mod_body) = rewritten_body {
                let _ = run_git_receive_pack_bytes(&bare_path, &mod_body, true);
            }
        }

        let (q_kind, title) = match &pre_eval.verdict {
            PushVerdictKind::BlockedProtectedBranch { branch } => (
                QueueItemKind::ProtectedBranchPush,
                format!("Push directo interceptado hacia rama protegida '{}'", branch),
            ),
            PushVerdictKind::BlockedForcePush { branch, .. } => (
                QueueItemKind::DestructiveGitOp,
                format!("Force-Push (reescritura de historial) en '{}'", branch),
            ),
            PushVerdictKind::BlockedRefDeletion { ref_name } => (
                QueueItemKind::DestructiveGitOp,
                format!("Eliminación de rama/ref remota '{}'", ref_name),
            ),
            PushVerdictKind::AllowedFastForward => unreachable!(),
        };

        let diff_sum = compute_bare_diff_summary(&bare_path, &first_ref, &parked_branch)
            .unwrap_or_else(|_| format!("{} -> {}", &old_sha[..8.min(old_sha.len())], &new_sha[..8.min(new_sha.len())]));

        let q_item = state
            .store
            .enqueue_item(
                q_kind,
                repo_name.clone(),
                title,
                pre_eval.human_reason.clone(),
                parked_branch.clone(),
                first_ref.clone(),
                old_sha,
                new_sha,
                true,
                wcfg.default_vcs.clone(),
                diff_sum,
            )
            .ok();

        let q_id_note = q_item
            .map(|i| format!("\n📋 Encolado en gitOlorin como Pendiente #{} (Revisa en http://127.0.0.1:{} y aprueba con Huella/PIN).", i.id, state.port))
            .unwrap_or_default();

        state.store.add_audit(
            &repo_name,
            "agent",
            "git_push_intercepted",
            false,
            &format!("{}{}", pre_eval.human_reason, q_id_note),
        );
        send_os_notification(
            "🧙‍♂️ gitOlorin: YOU SHALL NOT PASS!",
            &format!("Repo '{}': {}", repo_name, pre_eval.human_reason),
        );

        let rejection_pkt = build_git_receive_pack_rejection(
            &first_ref,
            &format!("{}{}", pre_eval.human_reason, q_id_note),
        );
        return (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/x-git-receive-pack-result",
            )],
            rejection_pkt,
        )
            .into_response();
    }

    // 2. Execute git-receive-pack against our bare staging repository.
    // Our pre-receive hook inside the bare repo will also verify fast-forward ancestry once the pack is unpacked!
    let (stdout, stderr, success) = match run_git_receive_pack_bytes(&bare_path, &body, false) {
        Ok(res) => res,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Check if the pre-receive hook caught a non-fast-forward force push
    if !success || stderr.contains("YOU SHALL NOT PASS") || String::from_utf8_lossy(&stdout).contains("pre-receive hook declined") {
        let first_ref = updates
            .first()
            .map(|u| u.ref_name.clone())
            .unwrap_or_else(|| "refs/heads/unknown".to_string());
        let old_sha = updates
            .first()
            .map(|u| u.old_sha.clone())
            .unwrap_or_else(|| ZERO_SHA.to_string());
        let new_sha = updates
            .first()
            .map(|u| u.new_sha.clone())
            .unwrap_or_else(|| ZERO_SHA.to_string());

        // Park the force-pushed objects into a temporary branch so if the human approves the force-push later,
        // the objects are preserved inside the bare staging repo!
        let mut parked_branch = first_ref.clone();
        if new_sha != ZERO_SHA {
            parked_branch = format!("refs/heads/olorin-force-{}", &new_sha[..7.min(new_sha.len())]);
            if let Some(mod_body) = rewrite_first_ref_in_receive_pack(&body, &first_ref, &parked_branch) {
                let _ = run_git_receive_pack_bytes(&bare_path, &mod_body, true);
            }
        }

        let _ = state.store.enqueue_item(
            QueueItemKind::DestructiveGitOp,
            repo_name.clone(),
            format!("Force-push (non-fast-forward) interceptado en '{}'", first_ref),
            "El agente intentó reescribir historial en una rama existente (--force).".to_string(),
            parked_branch,
            first_ref.clone(),
            old_sha,
            new_sha,
            true,
            wcfg.default_vcs,
            stderr.clone(),
        );
        state.store.add_audit(
            &repo_name,
            "agent",
            "force_push_blocked",
            false,
            &format!("Force-push bloqueado por pre-receive hook en {}", first_ref),
        );
        send_os_notification(
            "🧙‍♂️ gitOlorin: YOU SHALL NOT PASS!",
            &format!("Repo '{}': Force-push (non-fast-forward) bloqueado en {}", repo_name, first_ref),
        );
    } else {
        // 3. Clean fast-forward push on a feature branch (`feat/*`, `agent/*`)!
        // If this repository is already synced with GitHub and we have a low-privilege Worker Token,
        // forward the feature branch to GitHub automatically!
        if let Some(managed) = state.store.get_repo(&repo_name) {
            for u in &updates {
                state.store.add_audit(
                    &repo_name,
                    "agent",
                    "feature_branch_push",
                    true,
                    &format!("Push fast-forward permitido en {}", u.ref_name),
                );
                if managed.github_synced {
                    if let Some(ref w_token) = wcfg.worker_token {
                        let _ = sync_bare_branch_to_github(
                            &bare_path,
                            &wcfg.github_username,
                            &repo_name,
                            w_token,
                            &u.ref_name,
                        );
                    }
                }
            }
        }
    }

    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/x-git-receive-pack-result",
        )],
        stdout,
    )
        .into_response()
}

fn send_os_notification(title: &str, body: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("notify-send")
            .args(["-a", "gitOlorin", "-i", "gitolorin", title, body])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            body.replace('"', "'"),
            title.replace('"', "'")
        );
        let _ = Command::new("osascript")
            .args(["-e", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (title, body);
    }
}

fn run_git_receive_pack_bytes(
    bare_path: &std::path::Path,
    body: &[u8],
    admin_override: bool,
) -> anyhow::Result<(Vec<u8>, String, bool)> {
    let mut cmd = Command::new("git");
    if admin_override {
        cmd.env("GITOLORIN_ADMIN_OVERRIDE", "1");
    }
    let mut child = cmd
        .args(["receive-pack", "--stateless-rpc"])
        .arg(bare_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(body);
    }

    let out = child.wait_with_output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    Ok((out.stdout, stderr, out.status.success()))
}

/// Rewrites the first pkt-line ref target in a `git-receive-pack` stream so we can park
/// an intercepted push to `refs/heads/main` into `refs/heads/olorin-parked-<sha>` safely.
fn rewrite_first_ref_in_receive_pack(
    body: &[u8],
    old_ref: &str,
    new_ref: &str,
) -> Option<Vec<u8>> {
    if body.len() < 4 {
        return None;
    }
    let len_hex = std::str::from_utf8(&body[0..4]).ok()?;
    let pkt_len = usize::from_str_radix(len_hex, 16).ok()?;
    if pkt_len < 4 || pkt_len > body.len() {
        return None;
    }

    let first_payload = &body[4..pkt_len];
    let old_bytes = old_ref.as_bytes();
    let pos = first_payload
        .windows(old_bytes.len())
        .position(|w| w == old_bytes)?;

    let mut new_payload = Vec::new();
    // If replaced ref is created fresh, also zero out old_sha so receive-pack accepts creating the parked branch
    if first_payload.len() >= 40 {
        new_payload.extend_from_slice(ZERO_SHA.as_bytes());
        new_payload.extend_from_slice(&first_payload[40..pos]);
    } else {
        new_payload.extend_from_slice(&first_payload[..pos]);
    }
    new_payload.extend_from_slice(new_ref.as_bytes());
    new_payload.extend_from_slice(&first_payload[pos + old_bytes.len()..]);

    let new_pkt_len = new_payload.len() + 4;
    let mut out = format!("{:04x}", new_pkt_len).into_bytes();
    out.extend_from_slice(&new_payload);
    out.extend_from_slice(&body[pkt_len..]);
    Some(out)
}

// ============================================================================
// REST API Endpoints for Web UI & CLI
// ============================================================================

async fn api_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let db = state.store.snapshot();
    let vault_status = state.vault.get_public_status();
    let vcs_tools = check_vcs_tools(&state.base_dir);

    let mut repos_list: Vec<_> = db.repos.values().cloned().collect();
    repos_list.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let mut queue_list = db.queue.clone();
    queue_list.sort_by(|a, b| b.id.cmp(&a.id));

    let pending_count = queue_list
        .iter()
        .filter(|q| matches!(q.status, QueueItemStatus::Pending | QueueItemStatus::ApprovedForBatch))
        .count();
    let ready_batch_count = queue_list
        .iter()
        .filter(|q| q.status == QueueItemStatus::ApprovedForBatch)
        .count();

    Json(serde_json::json!({
        "app": "gitOlorin",
        "version": "0.1.0",
        "proxy_url": format!("http://127.0.0.1:{}", state.port),
        "autostart_enabled": crate::autostart::is_autostart_enabled(),
        "vault": vault_status,
        "vcs_tools": vcs_tools,
        "templates": crate::templates::list_templates(&state.base_dir),
        "repos": repos_list,
        "queue": queue_list,
        "audit_log": db.audit_log,
        "counts": {
            "pending_total": pending_count,
            "ready_for_batch": ready_batch_count,
            "repos_total": repos_list.len(),
        }
    }))
}

#[derive(Deserialize)]
struct AutostartReq {
    enabled: bool,
}

async fn api_autostart(Json(req): Json<AutostartReq>) -> Response {
    match crate::autostart::set_autostart(req.enabled) {
        Ok(msg) => Json(serde_json::json!({
            "ok": true,
            "enabled": crate::autostart::is_autostart_enabled(),
            "message": msg
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct VaultSetupReq {
    github_username: String,
    admin_pat: String,
    worker_token: Option<String>,
    pin: String,
    os_bio_enabled: bool,
    webauthn_cred_id: Option<String>,
    default_vcs: Option<String>,
}

async fn api_vault_setup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VaultSetupReq>,
) -> Response {
    let secret = AdminSecret {
        github_username: req.github_username.trim().to_string(),
        admin_pat: req.admin_pat.trim().to_string(),
        worker_pat_or_app_token: req.worker_token.unwrap_or_default().trim().to_string(),
    };

    if let Some(vcs) = req.default_vcs {
        let mut wcfg = state.vault.load_worker_config();
        wcfg.default_vcs = vcs;
        let _ = state.vault.save_worker_config(&wcfg);
    }

    match state
        .vault
        .seal_vault(&secret, &req.pin, req.os_bio_enabled, req.webauthn_cred_id)
    {
        Ok(()) => {
            state.store.add_audit(
                "system",
                "human-owner",
                "vault_sealed",
                true,
                "Bóveda Admin AES-256-GCM + Argon2id configurada y sellada.",
            );
            Json(serde_json::json!({
                "ok": true,
                "message": "Bóveda Admin encriptada (AES-256-GCM) y protegida con tu Huella/PIN."
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_check_repo_name(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let name = params.get("name").map(|s| s.trim()).unwrap_or("").to_string();
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');

    if !valid {
        return Json(serde_json::json!({
            "ok": false,
            "valid": false,
            "message": "Nombre inválido (usa solo letras, números, guiones o puntos)."
        }));
    }

    let exists_local = state.store.get_repo(&name).is_some();
    let owner = state.vault.load_worker_config().github_username;
    let name_clone = name.clone();
    let owner_clone = owner.clone();

    let (exists_in_owner, exact_public_matches) = tokio::task::spawn_blocking(move || {
        let mut in_owner = false;
        if !owner_clone.is_empty() {
            let url = format!("https://api.github.com/repos/{}/{}", owner_clone, name_clone);
            if let Ok(out) = Command::new("curl")
                .args([
                    "-sS",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "-H",
                    "User-Agent: gitolorin/0.1.0",
                    &url,
                ])
                .output()
            {
                let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if code == "200" {
                    in_owner = true;
                }
            }
        }

        let mut matches: Vec<String> = Vec::new();
        let search_url = format!(
            "https://api.github.com/search/repositories?q={}+in:name&per_page=5",
            name_clone
        );
        if let Ok(out) = Command::new("curl")
            .args([
                "-sS",
                "-H",
                "User-Agent: gitolorin/0.1.0",
                &search_url,
            ])
            .output()
        {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                if let Some(items) = val.get("items").and_then(|v| v.as_array()) {
                    for it in items {
                        let rname = it.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let full = it.get("full_name").and_then(|v| v.as_str()).unwrap_or("");
                        if rname.eq_ignore_ascii_case(&name_clone) && !full.is_empty() {
                            matches.push(full.to_string());
                            if matches.len() >= 3 {
                                break;
                            }
                        }
                    }
                }
            }
        }

        (in_owner, matches)
    })
    .await
    .unwrap_or((false, Vec::new()));

    Json(serde_json::json!({
        "ok": true,
        "valid": true,
        "name": name,
        "owner": owner,
        "exists_local": exists_local,
        "exists_in_owner": exists_in_owner,
        "exact_public_matches": exact_public_matches,
    }))
}

#[derive(Deserialize)]
struct RepoInitReq {
    name: String,
    display_name: Option<String>,
    template_id: Option<String>,
    license: Option<String>,
    local_only: Option<bool>,
    workspace_path: Option<String>,
    private: Option<bool>,
    vcs_mode: Option<String>,
    /// If provided (interactive owner mode), unlocks Admin Vault immediately and creates repo on GitHub right now
    unlock_mode: Option<String>, // "agent_queue" | "pin" | "os_bio"
    pin: Option<String>,
}

async fn api_templates_list(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let list = crate::templates::list_templates(&state.base_dir);
    Json(serde_json::json!({
        "ok": true,
        "templates": list,
        "templates_dir": crate::templates::templates_root(&state.base_dir).to_string_lossy()
    }))
}

#[derive(Deserialize)]
struct SaveTemplateReq {
    id: String,
    name: String,
    description: Option<String>,
    files: HashMap<String, String>,
}

async fn api_templates_save(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SaveTemplateReq>,
) -> Response {
    match crate::templates::save_custom_template(
        &state.base_dir,
        &req.id,
        &req.name,
        &req.description.unwrap_or_default(),
        req.files,
    ) {
        Ok(tpl) => Json(serde_json::json!({ "ok": true, "template": tpl })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_templates_delete(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    match crate::templates::delete_template(&state.base_dir, &id) {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_repo_init(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RepoInitReq>,
) -> Response {
    let wcfg = state.vault.load_worker_config();
    let vcs_mode = req.vcs_mode.unwrap_or_else(|| wcfg.default_vcs.clone());
    let private = req.private.unwrap_or(true);
    let ws_path = req
        .workspace_path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/home/edu/git/pub/{}", req.name.trim())));

    let unlock_mode = req.unlock_mode.unwrap_or_else(|| "agent_queue".to_string());
    let admin_secret_opt = match unlock_mode.as_str() {
        "pin" => {
            let pin = req.pin.unwrap_or_default();
            match state.vault.unseal_with_pin(&pin) {
                Ok(s) => Some(s),
                Err(e) => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
                    )
                        .into_response()
                }
            }
        }
        "os_bio" => match state
            .vault
            .unseal_with_os_biometrics(&format!("gitOlorin: Crear repositorio {}", req.name))
        {
            Ok(s) => Some(s),
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
                )
                    .into_response()
            }
        },
        _ => None,
    };

    let display_name = req.display_name.unwrap_or_default();
    let template_id = req.template_id.unwrap_or_else(|| "empty".to_string());
    let license = req.license.unwrap_or_else(|| "MIT".to_string());
    let local_only = req.local_only.unwrap_or(false);

    match initialize_managed_repository(
        &state.base_dir,
        &state.store,
        &req.name,
        &display_name,
        &template_id,
        &license,
        &wcfg.github_username,
        &ws_path,
        private,
        &vcs_mode,
        state.port,
        admin_secret_opt.as_ref(),
        local_only,
    )
    .await
    {
        Ok(res) => Json(serde_json::json!({
            "ok": true,
            "result": res
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct MrCreateReq {
    repo_name: String,
    source_branch: String,
    target_branch: Option<String>,
    title: String,
    description: Option<String>,
}

async fn api_mr_create(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MrCreateReq>,
) -> Response {
    let target = req.target_branch.unwrap_or_else(|| "main".to_string());
    let bare_path = state
        .store
        .staging_dir
        .join(format!("{}.git", req.repo_name.trim()));
    if !bare_path.is_dir() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "Repositorio no encontrado en staging de gitOlorin" })),
        )
            .into_response();
    }

    let diff_sum = compute_bare_diff_summary(
        &bare_path,
        &format!("refs/heads/{}", target),
        &format!("refs/heads/{}", req.source_branch),
    )
    .unwrap_or_else(|_| "Diff pendiente de revisión".to_string());

    let wcfg = state.vault.load_worker_config();
    match state.store.enqueue_item(
        QueueItemKind::MergeRequest,
        req.repo_name.clone(),
        req.title.clone(),
        req.description
            .unwrap_or_else(|| format!("Merge {} -> {}", req.source_branch, target)),
        req.source_branch.clone(),
        target.clone(),
        ZERO_SHA.to_string(),
        "HEAD".to_string(),
        true,
        wcfg.default_vcs,
        diff_sum,
    ) {
        Ok(item) => {
            state.store.add_audit(
                &req.repo_name,
                "agent",
                "mr_queued",
                true,
                &format!(
                    "MR #{}: '{}' ({} -> {}) encolado para revisión.",
                    item.id, item.title, item.source_branch, item.target_branch
                ),
            );
            Json(serde_json::json!({ "ok": true, "item": item })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_queue_toggle(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
) -> Response {
    let db = state.store.snapshot();
    let cur = match db.queue.iter().find(|i| i.id == id) {
        Some(i) => i.status.clone(),
        None => return (StatusCode::NOT_FOUND, "Queue item not found").into_response(),
    };

    let next_status = match cur {
        QueueItemStatus::Pending => QueueItemStatus::ApprovedForBatch,
        QueueItemStatus::ApprovedForBatch => QueueItemStatus::Pending,
        other => other,
    };

    match state.store.set_item_status(id, next_status, None) {
        Ok(Some(item)) => Json(serde_json::json!({ "ok": true, "item": item })).into_response(),
        _ => (StatusCode::BAD_REQUEST, "Could not toggle status").into_response(),
    }
}

async fn api_queue_reject(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
) -> Response {
    match state
        .store
        .set_item_status(id, QueueItemStatus::Rejected, None)
    {
        Ok(Some(item)) => {
            state.store.add_audit(
                &item.repo_name,
                "human-owner",
                "queue_item_rejected",
                true,
                &format!("Ítem #{} ('{}') rechazado.", item.id, item.title),
            );
            Json(serde_json::json!({ "ok": true, "item": item })).into_response()
        }
        _ => (StatusCode::NOT_FOUND, "Item not found").into_response(),
    }
}

async fn api_queue_diff(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
) -> Response {
    let db = state.store.snapshot();
    let item = match db.queue.iter().find(|i| i.id == id) {
        Some(i) => i,
        None => return (StatusCode::NOT_FOUND, "Queue item not found").into_response(),
    };
    let bare_path = state
        .store
        .staging_dir
        .join(format!("{}.git", item.repo_name));

    let src = if item.source_branch.starts_with("refs/") {
        item.source_branch.clone()
    } else {
        format!("refs/heads/{}", item.source_branch)
    };
    let tgt = if item.target_branch.starts_with("refs/") {
        item.target_branch.clone()
    } else {
        format!("refs/heads/{}", item.target_branch)
    };

    let out = Command::new("git")
        .arg("--git-dir")
        .arg(&bare_path)
        .args(["diff", &format!("{}...{}", tgt, src)])
        .output();

    let diff_text = match out {
        Ok(o) if o.status.success() && !o.stdout.is_empty() => {
            String::from_utf8_lossy(&o.stdout).to_string()
        }
        _ => item.diff_summary.clone(),
    };

    Json(serde_json::json!({
        "ok": true,
        "id": item.id,
        "title": item.title,
        "diff": diff_text
    }))
    .into_response()
}

#[derive(Deserialize)]
struct BatchApproveReq {
    /// "pin" | "os_bio"
    auth_method: String,
    pin: Option<String>,
    /// Optional explicit list of item IDs; if empty, executes all items marked `ApprovedForBatch` (or all `Pending` if approve_all is true)
    item_ids: Option<Vec<u64>>,
    approve_all_pending: Option<bool>,
}

/// Unlocks the Admin Vault ONCE using Fingerprint / OS Biometrics or PIN in RAM,
/// executes all selected MRs and pending Repo Creations in batch, and immediately zeroes the key in RAM!
async fn api_approve_batch(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BatchApproveReq>,
) -> Response {
    let secret = match req.auth_method.as_str() {
        "os_bio" => match state.vault.unseal_with_os_biometrics(
            "gitOlorin: Desbloquear Bóveda Admin para aprobar lote de MRs y Repositorios",
        ) {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
                )
                    .into_response()
            }
        },
        _ => {
            let pin = req.pin.unwrap_or_default();
            match state.vault.unseal_with_pin(&pin) {
                Ok(s) => s,
                Err(e) => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
                    )
                        .into_response()
                }
            }
        }
    };

    let db = state.store.snapshot();
    let approve_all = req.approve_all_pending.unwrap_or(false);
    let explicit_ids = req.item_ids.unwrap_or_default();

    let targets: Vec<_> = db
        .queue
        .into_iter()
        .filter(|item| {
            if !explicit_ids.is_empty() {
                explicit_ids.contains(&item.id)
                    && matches!(
                        item.status,
                        QueueItemStatus::Pending | QueueItemStatus::ApprovedForBatch
                    )
            } else if approve_all {
                matches!(
                    item.status,
                    QueueItemStatus::Pending | QueueItemStatus::ApprovedForBatch
                )
            } else {
                item.status == QueueItemStatus::ApprovedForBatch
            }
        })
        .collect();

    if targets.is_empty() {
        return Json(serde_json::json!({
            "ok": true,
            "executed": [],
            "message": "No había elementos marcados listos para aprobar en la cola."
        }))
        .into_response();
    }

    let mut results = Vec::new();
    for item in targets {
        match execute_approved_queue_item(&state.store, &item, &secret).await {
            Ok(msg) => {
                results.push(serde_json::json!({
                    "id": item.id,
                    "title": item.title,
                    "ok": true,
                    "message": msg
                }));
            }
            Err(e) => {
                let err_str = e.to_string();
                let _ = state.store.set_item_status(
                    item.id,
                    QueueItemStatus::Failed,
                    Some(err_str.clone()),
                );
                results.push(serde_json::json!({
                    "id": item.id,
                    "title": item.title,
                    "ok": false,
                    "error": err_str
                }));
            }
        }
    }

    // `secret` is dropped right here at the end of scope -> `ZeroizeOnDrop` wipes the Admin PAT from RAM!
    drop(secret);

    Json(serde_json::json!({
        "ok": true,
        "executed": results,
        "message": format!("Lote de {} operación(es) procesado y Bóveda Admin cerrada en RAM.", results.len())
    }))
    .into_response()
}
