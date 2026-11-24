use crate::inspector::{
    compute_bare_diff_summary, install_staging_pre_receive_hook,
};
use crate::queue::{ManagedRepo, QueueItem, QueueItemKind, QueueItemStatus, StateStore};
use crate::vault::AdminSecret;
use crate::vcs::{ensure_jj_installed, inject_agents_md};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroize;

pub fn validate_repo_name(raw: &str) -> Result<String> {
    let clean = raw.trim();
    if clean.is_empty()
        || clean.len() > 100
        || clean.starts_with('-')
        || clean.starts_with('.')
        || clean.contains("..")
        || !clean
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(anyhow!(
            "Nombre de repositorio inválido '{}'. Usa solo letras, números, guiones o puntos (sin empezar con '-' o '.', ni '..').",
            clean
        ));
    }
    Ok(clean.to_string())
}

pub fn validate_github_https_url(raw: &str) -> Result<()> {
    const PREFIX: &str = "https://github.com/";
    if !raw.starts_with(PREFIX)
        || raw.chars().any(|c| c.is_whitespace() || c.is_control())
        || raw.contains('@')
        || raw.contains('?')
        || raw.contains('#')
        || raw.contains("..")
    {
        return Err(anyhow!(
            "URL de GitHub inválida o potencialmente insegura: solo se permite https://github.com/<owner>/<repo>[.git]"
        ));
    }

    let rest = &raw[PREFIX.len()..];
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow!(
            "URL de GitHub inválida: debe tener exactamente formato https://github.com/<owner>/<repo>"
        ));
    }

    let owner = parts[0];
    let repo_part = parts[1];
    if owner.is_empty()
        || owner.starts_with('-')
        || owner.starts_with('.')
        || !owner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(anyhow!("Propietario inválido en URL de GitHub."));
    }

    let repo_clean = repo_part.strip_suffix(".git").unwrap_or(repo_part);
    validate_repo_name(repo_clean)?;
    Ok(())
}

pub fn validate_token_for_header(token: &str) -> Result<&str> {
    let clean = token.trim();
    if clean.is_empty()
        || clean.contains('\r')
        || clean.contains('\n')
        || clean.contains('\0')
        || clean.contains('"')
        || clean.contains('\\')
        || clean.chars().any(|c| c.is_control())
    {
        return Err(anyhow!(
            "El token contiene caracteres inválidos para cabecera HTTP."
        ));
    }
    Ok(clean)
}

pub fn redact_secret(text: &str, token: &str) -> String {
    let clean = token.trim();
    if clean.is_empty() {
        return text.to_string();
    }
    let mut out = text.replace(clean, "[REDACTED]");
    let mut raw_basic = format!("x-access-token:{}", clean);
    let mut b64 = B64.encode(raw_basic.as_bytes());
    out = out.replace(&b64, "[REDACTED]");
    raw_basic.zeroize();
    b64.zeroize();
    out
}

fn run_github_api_curl(
    method: &str,
    url: &str,
    token: &str,
    json_body: Option<&str>,
) -> Result<Vec<u8>> {
    if !url.starts_with("https://api.github.com/") {
        return Err(anyhow!("URL de API GitHub no permitida."));
    }
    let clean_token = validate_token_for_header(token)?;

    let mut cmd = Command::new("curl");
    cmd.args([
        "-sS",
        "-X",
        method,
        url,
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        "X-GitHub-Api-Version: 2022-11-28",
        "-H",
        "User-Agent: gitolorin/0.1.0",
        "--config",
        "-",
    ]);
    if let Some(body) = json_body {
        cmd.args(["-d", body]);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Ejecutando curl hacia GitHub API")?;

    let mut cfg = format!("header = \"Authorization: Bearer {}\"\n", clean_token);
    if let Some(mut stdin) = child.stdin.take() {
        let wres = stdin.write_all(cfg.as_bytes());
        cfg.zeroize();
        wres.context("Enviando cabecera de autorización por stdin a curl")?;
    } else {
        cfg.zeroize();
    }

    let out = child
        .wait_with_output()
        .context("Esperando respuesta de GitHub API")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!(
            "Error llamando a GitHub API: {}",
            redact_secret(stderr.trim(), clean_token)
        ));
    }
    Ok(out.stdout)
}

fn run_git_with_github_auth(
    git_dir: Option<&Path>,
    cwd: Option<&Path>,
    args: &[&str],
    token: &str,
) -> Result<std::process::Output> {
    let clean_token = validate_token_for_header(token)?;
    let mut raw = format!("x-access-token:{}", clean_token);
    let mut basic = B64.encode(raw.as_bytes());
    let mut auth_header = format!("AUTHORIZATION: basic {}", basic);

    let mut cmd = Command::new("git");
    if let Some(gd) = git_dir {
        cmd.arg("--git-dir").arg(gd);
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "http.https://github.com/.extraheader")
        .env("GIT_CONFIG_VALUE_0", &auth_header);

    let res = cmd.output();
    raw.zeroize();
    basic.zeroize();
    auth_header.zeroize();

    res.context("Ejecutando comando git autenticado hacia GitHub")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitRepoResult {
    pub repo: ManagedRepo,
    pub mode: String, // "github_live" | "local_staging_queued"
    pub queued_item_id: Option<u64>,
    pub message: String,
}

/// Initializes a repository either:
/// - **Proactively by an Agent (`admin_secret == None`)**: Creates a local bare staging repository immediately,
///   configures the project directory with `.git` + optional `jj` (`--colocate`), injects `AGENTS.md`,
///   sets `origin` to `http://127.0.0.1:9418/git/<name>.git`, switches to `agent/main` or `feat/initial`,
///   and queues a `CreateRepo` item in the human approval queue!
/// - **Interactively by the Human Owner (`admin_secret == Some(...)`)**: Creates the repository on GitHub immediately
///   via the GitHub REST API, sets up the local bare staging mirror + project workspace, and syncs `main`.
pub async fn initialize_managed_repository(
    base_dir: &Path,
    store: &StateStore,
    repo_name: &str,
    display_name: &str,
    template_id: &str,
    license: &str,
    owner: &str,
    workspace_dir: &Path,
    private: bool,
    vcs_mode: &str,
    proxy_port: u16,
    admin_secret: Option<&AdminSecret>,
    local_only: bool,
) -> Result<InitRepoResult> {
    let clean_name_buf = validate_repo_name(repo_name)?;
    let clean_name = clean_name_buf.as_str();

    // 1. Create the bare staging repository inside ~/.gitolorin/staging/<name>.git
    let bare_path = store.staging_dir.join(format!("{}.git", clean_name));
    if !bare_path.is_dir() {
        fs::create_dir_all(&bare_path)?;
        let st = Command::new("git")
            .args(["init", "--bare", "-b", "main"])
            .arg(&bare_path)
            .status()
            .context("Inicializando repositorio bare de staging en gitOlorin")?;
        if !st.success() {
            return Err(anyhow!("Error ejecutando git init --bare"));
        }
        // Enable http.receivepack so Git Smart HTTP clients can push to this bare repo
        let _ = Command::new("git")
            .arg("--git-dir")
            .arg(&bare_path)
            .args(["config", "http.receivepack", "true"])
            .status();
        install_staging_pre_receive_hook(&bare_path)?;
    }

    // 2. Generate unique per-project proxy token
    let existing_repo = store.get_repo(clean_name);
    let project_token = existing_repo
        .as_ref()
        .map(|r| r.project_proxy_token.clone())
        .unwrap_or_else(|| {
            let mut b = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut b);
            format!("olo_{}", hex::encode(b))
        });

    // 3. Prepare the working directory
    fs::create_dir_all(workspace_dir)?;
    let dot_git = workspace_dir.join(".git");
    if !dot_git.exists() {
        let _ = Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(workspace_dir)
            .status()?;
    }

    // Ensure local git user.name / user.email are configured so initial commit succeeds
    let has_user = Command::new("git")
        .args(["config", "user.name"])
        .current_dir(workspace_dir)
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if !has_user {
        let _ = Command::new("git")
            .args(["config", "user.name", if owner.is_empty() { "developer" } else { owner }])
            .current_dir(workspace_dir)
            .status();
        let _ = Command::new("git")
            .args([
                "config",
                "user.email",
                &format!("{}@users.noreply.github.com", if owner.is_empty() { "developer" } else { owner }),
            ])
            .current_dir(workspace_dir)
            .status();
    }

    let authed_proxy_url = format!(
        "http://x-olorin:{}@127.0.0.1:{}/git/{}.git",
        project_token, proxy_port, clean_name
    );
    let clean_proxy_url = format!("http://127.0.0.1:{}/git/{}.git", proxy_port, clean_name);

    // Set origin to our local gitOlorin proxy
    let has_origin = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(workspace_dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if has_origin {
        let _ = Command::new("git")
            .args(["remote", "set-url", "origin", &authed_proxy_url])
            .current_dir(workspace_dir)
            .status();
    } else {
        let _ = Command::new("git")
            .args(["remote", "add", "origin", &authed_proxy_url])
            .current_dir(workspace_dir)
            .status();
    }

    // 4. Inject AGENTS.md with instructions for the chosen VCS ("jj", "worktree", or "git")
    if vcs_mode == "jj" {
        let _ = ensure_jj_installed(base_dir).await;
        if !workspace_dir.join(".jj").is_dir() {
            let jj_status = crate::vcs::check_vcs_tools(base_dir);
            if let Some(jj_bin) = jj_status.jj_path {
                let _ = Command::new(jj_bin)
                    .args(["git", "init", "--colocate"])
                    .current_dir(workspace_dir)
                    .status();
            }
        }
    }
    inject_agents_md(workspace_dir, clean_name, vcs_mode, &clean_proxy_url)?;
    let _ = crate::templates::apply_template(
        base_dir,
        template_id,
        workspace_dir,
        clean_name,
        display_name,
        owner,
        license,
    );
    crate::templates::write_license_file(workspace_dir, license, owner)?;

    // 5. Create initial commit on `main` if the repo has no commits yet, and push it to bare staging with admin override
    let has_head = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(workspace_dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !has_head {
        let _ = Command::new("git")
            .args(["add", "-A"])
            .current_dir(workspace_dir)
            .status();
        let _ = Command::new("git")
            .args(["commit", "-m", "chore: initialize repository with gitOlorin guardrails"])
            .current_dir(workspace_dir)
            .status();
    }

    // Seed bare staging repo directly from workspace main
    let _ = Command::new("git")
        .env("GITOLORIN_ADMIN_OVERRIDE", "1")
        .args(["push", &bare_path.to_string_lossy(), "HEAD:refs/heads/main"])
        .current_dir(workspace_dir)
        .status();

    // Switch workspace to a safe working branch (`feat/initial`) so the agent is not sitting on `main`
    let current_branch = Command::new("git")
        .args(["symbolic-ref", "--short", "HEAD"])
        .current_dir(workspace_dir)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "main".to_string());
    if current_branch == "main" || current_branch == "master" || current_branch.is_empty() {
        let _ = Command::new("git")
            .args(["checkout", "-B", "feat/initial"])
            .current_dir(workspace_dir)
            .status();
    }

    // 6. Decide whether to create immediately on GitHub (if Admin Vault unlocked) or queue for Batch Approval
    let mut github_synced = false;
    let mut github_url = None;
    let mut queued_item_id = None;
    let mode;
    let message;

    let effective_desc = if display_name.trim().is_empty() {
        "Managed & protected by gitOlorin Bastion".to_string()
    } else {
        display_name.trim().to_string()
    };

    if let Some(secret) = admin_secret {
        let gh_url = create_github_repo_api(secret, clean_name, &effective_desc, private).await?;
        sync_bare_branch_to_github(
            &bare_path,
            &secret.github_username,
            clean_name,
            &secret.admin_pat,
            "main",
        )?;
        github_synced = true;
        github_url = Some(gh_url.clone());
        mode = "github_live".to_string();
        message = format!(
            "✅ Repositorio '{}' creado en GitHub ({}) y configurado con proxy gitOlorin ({}).",
            clean_name, gh_url, vcs_mode
        );
        store.add_audit(
            clean_name,
            "human-admin",
            "repo_create_github",
            true,
            &message,
        );
    } else if local_only || existing_repo.as_ref().map(|r| r.github_synced).unwrap_or(false) {
        if let Some(ref prev) = existing_repo {
            github_synced = prev.github_synced;
            github_url = prev.github_url.clone();
        }
        mode = if github_synced {
            "local_reinit_synced".to_string()
        } else {
            "local_only".to_string()
        };
        message = if github_synced {
            format!(
                "✅ Repositorio '{}' re-inicializado en local (preservando vínculo existente en GitHub).",
                clean_name
            )
        } else {
            format!(
                "✅ Repositorio '{}' inicializado en modo local (--local-only) sin encolar creación en GitHub.",
                clean_name
            )
        };
        store.add_audit(
            clean_name,
            "agent",
            "repo_init_local",
            true,
            &message,
        );
    } else {
        mode = "local_staging_queued".to_string();
        let existing_pending_id = store
            .snapshot()
            .queue
            .into_iter()
            .find(|q| {
                q.repo_name == clean_name
                    && q.kind == QueueItemKind::CreateRepo
                    && matches!(
                        q.status,
                        QueueItemStatus::Pending | QueueItemStatus::ApprovedForBatch
                    )
            })
            .map(|q| q.id);

        if let Some(existing_id) = existing_pending_id {
            queued_item_id = Some(existing_id);
            message = format!(
                "⏳ Repositorio '{}' actualizado en Staging Local ({}). Ya existe solicitud #{} pendiente en cola para crear en GitHub.",
                clean_name, clean_proxy_url, existing_id
            );
        } else {
            let diff_sum =
                compute_bare_diff_summary(&bare_path, "refs/heads/main", "refs/heads/main")
                    .unwrap_or_else(|_| {
                        "Repositorio nuevo inicializado en staging local.".to_string()
                    });
            let q_item = store.enqueue_item(
                QueueItemKind::CreateRepo,
                clean_name.to_string(),
                format!("Crear repositorio '{}' en GitHub y sincronizar", clean_name),
                format!(
                    "Solicitado en {} (Privado: {}, VCS: {}). El agente ya puede trabajar y hacer push contra el staging local sin esperarte.",
                    workspace_dir.display(),
                    private,
                    vcs_mode
                ),
                "main".to_string(),
                "main".to_string(),
                crate::inspector::ZERO_SHA.to_string(),
                "HEAD".to_string(),
                private,
                vcs_mode.to_string(),
                diff_sum,
            )?;
            queued_item_id = Some(q_item.id);
            message = format!(
                "⏳ Repositorio '{}' listo en Staging Local ({}). El agente ya puede hacer commits y push. Pendiente #{} en cola para crear en GitHub con tu Huella/PIN.",
                clean_name, clean_proxy_url, q_item.id
            );
        }
        store.add_audit(
            clean_name,
            "agent",
            "repo_init_staging",
            true,
            &message,
        );
    }

    let managed = ManagedRepo {
        name: clean_name.to_string(),
        display_name: display_name.trim().to_string(),
        template_id: template_id.trim().to_string(),
        owner: owner.to_string(),
        local_workspace_path: workspace_dir.to_string_lossy().to_string(),
        bare_staging_path: bare_path.to_string_lossy().to_string(),
        github_synced,
        github_url,
        private,
        vcs_mode: vcs_mode.to_string(),
        project_proxy_token: project_token,
        created_at: Utc::now().to_rfc3339(),
    };
    store.upsert_repo(managed.clone())?;

    Ok(InitRepoResult {
        repo: managed,
        mode,
        queued_item_id,
        message,
    })
}

/// Calls GitHub REST API `POST /user/repos` using the temporarily unlocked Admin PAT
pub async fn create_github_repo_api(
    secret: &AdminSecret,
    repo_name: &str,
    description: &str,
    private: bool,
) -> Result<String> {
    if secret.admin_pat.trim().starts_with("demo_") || secret.admin_pat.trim() == "local_only" {
        return Ok(format!(
            "https://github.com/{}/{}.git (Modo Demo/Local)",
            secret.github_username, repo_name
        ));
    }

    let desc_val = if description.trim().is_empty() {
        "Managed & protected by gitOlorin Bastion"
    } else {
        description.trim()
    };

    let payload = serde_json::json!({
        "name": repo_name,
        "private": private,
        "auto_init": false,
        "description": desc_val
    })
    .to_string();

    let stdout = run_github_api_curl(
        "POST",
        "https://api.github.com/user/repos",
        &secret.admin_pat,
        Some(&payload),
    )?;

    let body: serde_json::Value = serde_json::from_slice(&stdout).unwrap_or_default();

    if let Some(html_url) = body.get("html_url").and_then(|v| v.as_str()) {
        return Ok(html_url.to_string());
    }

    let err_msg = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("Error desconocido de GitHub API");
    if err_msg.to_lowercase().contains("name already exists") {
        return Ok(format!(
            "https://github.com/{}/{}",
            secret.github_username, repo_name
        ));
    }

    Err(anyhow!(
        "GitHub API rechazó la creación del repo: {}",
        redact_secret(err_msg, &secret.admin_pat)
    ))
}

/// Pushes a specific branch from our local bare staging repository to GitHub using GIT_CONFIG_*
/// environment variables scoped strictly to `https://github.com/` (never passed in argv or written to disk).
pub fn sync_bare_branch_to_github(
    bare_repo_path: &Path,
    github_user: &str,
    repo_name: &str,
    token: &str,
    branch_or_refspec: &str,
) -> Result<()> {
    if token.trim().is_empty() || token.trim().starts_with("demo_") || token.trim() == "local_only"
    {
        return Ok(());
    }

    let remote_url = format!("https://github.com/{}/{}.git", github_user, repo_name);
    validate_github_https_url(&remote_url)?;

    let refspec = if branch_or_refspec.contains(':') || branch_or_refspec.starts_with("refs/") {
        branch_or_refspec.to_string()
    } else {
        format!("refs/heads/{}:refs/heads/{}", branch_or_refspec, branch_or_refspec)
    };

    let out = run_git_with_github_auth(
        Some(bare_repo_path),
        None,
        &["push", "--", &remote_url, &refspec],
        token,
    )?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!(
            "Error empujando a GitHub: {}",
            redact_secret(stderr.trim(), token)
        ));
    }
    Ok(())
}

pub fn cleanup_parked_ref(bare_path: &Path, ref_name: &str) {
    if bare_path.is_dir()
        && (ref_name.starts_with("refs/olorin/")
            || ref_name.starts_with("refs/heads/olorin-parked-")
            || ref_name.starts_with("refs/heads/olorin-force-"))
    {
        let _ = Command::new("git")
            .arg("--git-dir")
            .arg(bare_path)
            .args(["update-ref", "-d", ref_name])
            .status();
    }
}

/// Executes a single approved QueueItem using the unlocked `AdminSecret`.
pub async fn execute_approved_queue_item(
    store: &StateStore,
    item: &QueueItem,
    secret: &AdminSecret,
) -> Result<String> {
    let repo = store
        .get_repo(&item.repo_name)
        .ok_or_else(|| anyhow!("Repositorio '{}' no encontrado en el registro", item.repo_name))?;
    let bare_path = PathBuf::from(&repo.bare_staging_path);

    match item.kind {
        QueueItemKind::CreateRepo => {
            let gh_url = create_github_repo_api(secret, &item.repo_name, &repo.display_name, item.private_repo).await?;
            // Sync all existing branches from local bare staging to GitHub
            if !secret.admin_pat.trim().starts_with("demo_") && secret.admin_pat.trim() != "local_only" {
                let remote_url = format!(
                    "https://github.com/{}/{}.git",
                    secret.github_username, item.repo_name
                );
                validate_github_https_url(&remote_url)?;
                let push_out = run_git_with_github_auth(
                    Some(&bare_path),
                    None,
                    &["push", "--all", "--", &remote_url],
                    &secret.admin_pat,
                )?;
                if !push_out.status.success() {
                    let stderr = String::from_utf8_lossy(&push_out.stderr);
                    return Err(anyhow!(
                        "Repo creado en GitHub, pero falló la sincronización de ramas: {}",
                        redact_secret(stderr.trim(), &secret.admin_pat)
                    ));
                }
            }
            store.mark_repo_synced(&item.repo_name, gh_url.clone())?;
            store.set_item_status(item.id, QueueItemStatus::Executed, None)?;
            if item.kind == QueueItemKind::ProtectedBranchPush {
                cleanup_parked_ref(&bare_path, &item.source_branch);
            }
            let msg = format!("Repo '{}' creado en GitHub ({}) y todas las ramas sincronizadas.", item.repo_name, gh_url);
            store.add_audit(&item.repo_name, "human-biometric", "approve_create_repo", true, &msg);
            Ok(msg)
        }
        QueueItemKind::MergeRequest | QueueItemKind::ProtectedBranchPush => {
            // Fast-forward or merge source_branch (or new_sha) into target_branch (e.g. main) inside bare repo
            let source_ref = if item.source_branch.starts_with("refs/") {
                item.source_branch.clone()
            } else if item.new_sha != "HEAD" && item.new_sha.len() == 40 {
                item.new_sha.clone()
            } else {
                format!("refs/heads/{}", item.source_branch)
            };
            let target_ref = if item.target_branch.starts_with("refs/") {
                item.target_branch.clone()
            } else {
                format!("refs/heads/{}", item.target_branch)
            };

            // Resolve source commit SHA
            let src_out = Command::new("git")
                .arg("--git-dir")
                .arg(&bare_path)
                .args(["rev-parse", "--verify", &source_ref])
                .output()?;
            if !src_out.status.success() {
                return Err(anyhow!(
                    "No se encontró la referencia origen '{}' en staging",
                    source_ref
                ));
            }
            let src_sha = String::from_utf8_lossy(&src_out.stdout).trim().to_string();

            // Update target branch ref in bare repo (or create merge commit if diverged)
            let tgt_out = Command::new("git")
                .arg("--git-dir")
                .arg(&bare_path)
                .args(["rev-parse", "--verify", &target_ref])
                .output()?;

            let final_sha = if tgt_out.status.success() {
                let tgt_sha = String::from_utf8_lossy(&tgt_out.stdout).trim().to_string();
                let is_ancestor = Command::new("git")
                    .arg("--git-dir")
                    .arg(&bare_path)
                    .args(["merge-base", "--is-ancestor", &tgt_sha, &src_sha])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);

                if is_ancestor {
                    src_sha.clone()
                } else {
                    // Perform an in-memory merge-tree (`git merge-tree --write-tree`) without needing a working copy!
                    let mt_out = Command::new("git")
                        .arg("--git-dir")
                        .arg(&bare_path)
                        .args(["merge-tree", "--write-tree", &tgt_sha, &src_sha])
                        .output()?;
                    if !mt_out.status.success() {
                        let conflict_info = String::from_utf8_lossy(&mt_out.stdout);
                        return Err(anyhow!(
                            "Conflicto de merge detectado entre {} y {}: {}",
                            item.source_branch,
                            item.target_branch,
                            conflict_info.lines().next().unwrap_or("conflicto")
                        ));
                    }
                    let tree_sha = String::from_utf8_lossy(&mt_out.stdout)
                        .lines()
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    let commit_msg = format!("Merge '{}' into '{}': {}", item.source_branch, item.target_branch, item.title);
                    let ct_out = Command::new("git")
                        .arg("--git-dir")
                        .arg(&bare_path)
                        .args([
                            "commit-tree",
                            &tree_sha,
                            "-p",
                            &tgt_sha,
                            "-p",
                            &src_sha,
                            "-m",
                            &commit_msg,
                        ])
                        .output()?;
                    if !ct_out.status.success() {
                        return Err(anyhow!("Error creando commit-tree en memoria"));
                    }
                    String::from_utf8_lossy(&ct_out.stdout).trim().to_string()
                }
            } else {
                src_sha.clone()
            };

            let up_st = Command::new("git")
                .arg("--git-dir")
                .arg(&bare_path)
                .args(["update-ref", &target_ref, &final_sha])
                .status()?;
            if !up_st.success() {
                return Err(anyhow!("Error actualizando ref {}", target_ref));
            }

            // If repo is synced to GitHub, push the updated main branch to GitHub using Admin PAT
            if repo.github_synced {
                sync_bare_branch_to_github(
                    &bare_path,
                    &secret.github_username,
                    &item.repo_name,
                    &secret.admin_pat,
                    &format!("{}:{}", final_sha, target_ref),
                )?;
            }

            store.set_item_status(item.id, QueueItemStatus::Executed, None)?;
            if item.kind == QueueItemKind::ProtectedBranchPush {
                cleanup_parked_ref(&bare_path, &item.source_branch);
            }
            let msg = format!(
                "MR #{} fusionado en '{}' (commit {}) y sincronizado.",
                item.id,
                item.target_branch,
                &final_sha[..8.min(final_sha.len())]
            );
            store.add_audit(&item.repo_name, "human-biometric", "approve_merge_main", true, &msg);
            Ok(msg)
        }
        QueueItemKind::DestructiveGitOp => {
            // Apply the requested force-push or ref deletion
            let target_ref = if item.target_branch.starts_with("refs/") {
                item.target_branch.clone()
            } else {
                format!("refs/heads/{}", item.target_branch)
            };

            if item.new_sha == crate::inspector::ZERO_SHA {
                let _ = Command::new("git")
                    .arg("--git-dir")
                    .arg(&bare_path)
                    .args(["update-ref", "-d", &target_ref])
                    .status()?;
            } else {
                let _ = Command::new("git")
                    .arg("--git-dir")
                    .arg(&bare_path)
                    .args(["update-ref", &target_ref, &item.new_sha])
                    .status()?;
            }

            store.set_item_status(item.id, QueueItemStatus::Executed, None)?;
            cleanup_parked_ref(&bare_path, &item.source_branch);
            let msg = format!(
                "Operación destructiva #{} aprobada y aplicada sobre '{}'.",
                item.id, target_ref
            );
            store.add_audit(&item.repo_name, "human-biometric", "approve_destructive_op", true, &msg);
            Ok(msg)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteGithubRepo {
    pub name: String,
    pub full_name: String,
    pub description: Option<String>,
    pub private: bool,
    pub html_url: String,
    pub clone_url: String,
    pub default_branch: String,
    pub updated_at: String,
    pub language: Option<String>,
    pub fork: bool,
    pub cloned_paths: Vec<String>,
    pub managed_by_gitolorin: bool,
    pub managed_workspace_path: Option<String>,
}

fn find_local_clone_paths(repo_name: &str, managed: Option<&ManagedRepo>) -> Vec<String> {
    let mut paths = Vec::new();
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let candidates = [
        home.join("git").join(repo_name),
        home.join("git").join("pub").join(repo_name),
    ];
    for c in candidates {
        if c.join(".git").exists() {
            paths.push(c.to_string_lossy().to_string());
        }
    }
    if let Some(m) = managed {
        let mp = PathBuf::from(&m.local_workspace_path);
        if mp.join(".git").exists() {
            let s = mp.to_string_lossy().to_string();
            if !paths.contains(&s) {
                paths.push(s);
            }
        }
    }
    paths
}

/// Lists remote repositories owned by the authenticated GitHub user and enriches them
/// with local clone tracking (`~/git/<name>`, `~/git/pub/<name>`, and gitOlorin managed repos).
pub async fn list_github_repos_api(
    secret: &AdminSecret,
    store: &StateStore,
) -> Result<Vec<RemoteGithubRepo>> {
    if secret.admin_pat.trim().starts_with("demo_") || secret.admin_pat.trim() == "local_only" {
        return Err(anyhow!(
            "La bóveda está en modo demo/local; configura un GitHub PAT real para listar repositorios remotos."
        ));
    }

    let stdout = run_github_api_curl(
        "GET",
        "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner",
        &secret.admin_pat,
        None,
    )?;

    let val: serde_json::Value = serde_json::from_slice(&stdout)
        .context("Parseando respuesta JSON de GitHub API /user/repos")?;

    let arr = match val.as_array() {
        Some(a) => a,
        None => {
            let err_msg = val
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Respuesta inesperada de GitHub API");
            return Err(anyhow!(
                "GitHub API error: {}",
                redact_secret(err_msg, &secret.admin_pat)
            ));
        }
    };

    let mut repos = Vec::with_capacity(arr.len());
    for item in arr {
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let managed = store.get_repo(&name);
        let cloned_paths = find_local_clone_paths(&name, managed.as_ref());
        repos.push(RemoteGithubRepo {
            name: name.clone(),
            full_name: item
                .get("full_name")
                .and_then(|v| v.as_str())
                .unwrap_or(&name)
                .to_string(),
            description: item
                .get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            private: item.get("private").and_then(|v| v.as_bool()).unwrap_or(false),
            html_url: item
                .get("html_url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            clone_url: item
                .get("clone_url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            default_branch: item
                .get("default_branch")
                .and_then(|v| v.as_str())
                .unwrap_or("main")
                .to_string(),
            updated_at: item
                .get("updated_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            language: item
                .get("language")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            fork: item.get("fork").and_then(|v| v.as_bool()).unwrap_or(false),
            cloned_paths,
            managed_by_gitolorin: managed.is_some(),
            managed_workspace_path: managed.map(|m| m.local_workspace_path),
        });
    }

    Ok(repos)
}

/// Clones a remote GitHub repository into `~/git/<name>` or `~/git/pub/<name>`,
/// sets up the local bare staging mirror, points `origin` through the gitOlorin proxy,
/// injects `AGENTS.md`, and optionally initializes `jj --colocate`.
pub async fn clone_github_repo(
    store: &StateStore,
    secret: &AdminSecret,
    repo_name: &str,
    clone_url: &str,
    html_url: &str,
    target_group: &str,
    private: bool,
    vcs_mode: &str,
    proxy_port: u16,
) -> Result<ManagedRepo> {
    let clean_name_buf = validate_repo_name(repo_name)?;
    let clean_name = clean_name_buf.as_str();
    validate_github_https_url(clone_url)?;
    if !html_url.trim().is_empty() {
        validate_github_https_url(html_url)?;
    }

    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let target_parent = match target_group {
        "git" => home.join("git"),
        "git/pub" => home.join("git").join("pub"),
        _ => return Err(anyhow!("Destino inválido '{}'. Usa 'git' o 'git/pub'.", target_group)),
    };
    fs::create_dir_all(&target_parent)?;
    let workspace_dir = target_parent.join(&clean_name);
    if workspace_dir.exists() {
        return Err(anyhow!(
            "El directorio '{}' ya existe localmente.",
            workspace_dir.display()
        ));
    }

    let workspace_dir_str = workspace_dir.to_string_lossy().to_string();
    let clone_out = run_git_with_github_auth(
        None,
        None,
        &["clone", "--", clone_url, &workspace_dir_str],
        &secret.admin_pat,
    )?;

    if !clone_out.status.success() {
        let stderr = String::from_utf8_lossy(&clone_out.stderr);
        return Err(anyhow!(
            "Error clonando desde GitHub: {}",
            redact_secret(stderr.trim(), &secret.admin_pat)
        ));
    }

    // Create or reuse bare staging repo in ~/.gitolorin/staging/<name>.git
    let bare_path = store.staging_dir.join(format!("{}.git", clean_name));
    if !bare_path.is_dir() {
        fs::create_dir_all(&bare_path)?;
        let st = Command::new("git")
            .args(["clone", "--bare"])
            .arg(&workspace_dir)
            .arg(&bare_path)
            .status()
            .context("Creando espejo bare de staging")?;
        if !st.success() {
            return Err(anyhow!("Error creando repositorio bare de staging"));
        }
        let _ = Command::new("git")
            .arg("--git-dir")
            .arg(&bare_path)
            .args(["config", "http.receivepack", "true"])
            .status();
        install_staging_pre_receive_hook(&bare_path)?;
    }

    let project_token = store
        .get_repo(&clean_name)
        .map(|r| r.project_proxy_token)
        .unwrap_or_else(|| {
            let mut b = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut b);
            format!("olo_{}", hex::encode(b))
        });

    // Point workspace origin to gitOlorin proxy with per-project proxy token (clean URL goes in AGENTS.md)
    let authed_proxy_origin = format!(
        "http://x-olorin:{}@127.0.0.1:{}/git/{}.git",
        project_token, proxy_port, clean_name
    );
    let clean_proxy_origin = format!("http://127.0.0.1:{}/git/{}.git", proxy_port, clean_name);
    let _ = Command::new("git")
        .args(["remote", "set-url", "origin", &authed_proxy_origin])
        .current_dir(&workspace_dir)
        .status();

    // Inject AGENTS.md & optional jj colocate
    let _ = inject_agents_md(&workspace_dir, clean_name, vcs_mode, &clean_proxy_origin);
    if vcs_mode == "jj" {
        let base_dir = store.staging_dir.parent().unwrap_or(&store.staging_dir);
        if let Ok(jj_bin) = ensure_jj_installed(base_dir).await {
            let _ = Command::new(jj_bin)
                .args(["git", "init", "--colocate"])
                .current_dir(&workspace_dir)
                .status();
        }
    }

    let managed = ManagedRepo {
        name: clean_name.to_string(),
        display_name: String::new(),
        template_id: String::new(),
        owner: secret.github_username.clone(),
        local_workspace_path: workspace_dir.to_string_lossy().to_string(),
        bare_staging_path: bare_path.to_string_lossy().to_string(),
        github_synced: true,
        github_url: Some(html_url.to_string()),
        private,
        vcs_mode: vcs_mode.to_string(),
        project_proxy_token: project_token,
        created_at: Utc::now().to_rfc3339(),
    };

    store.upsert_repo(managed.clone())?;
    store.add_audit(
        clean_name,
        "human-owner",
        "clone_github_repo",
        true,
        &format!("Clonado desde GitHub en {}", workspace_dir.display()),
    );

    Ok(managed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_github_https_url() {
        assert!(validate_github_https_url("https://github.com/octocat/hello-world.git").is_ok());
        assert!(validate_github_https_url("https://github.com/octocat/repo_1.2").is_ok());

        // Reject evil domains, userinfo tricks, http, flag injection, queries, traversal, control chars
        assert!(validate_github_https_url("https://evil.com/octocat/repo.git").is_err());
        assert!(validate_github_https_url("https://github.com@evil.com/octocat/repo.git").is_err());
        assert!(validate_github_https_url("http://github.com/octocat/repo.git").is_err());
        assert!(validate_github_https_url("--upload-pack=evil").is_err());
        assert!(validate_github_https_url("https://github.com/octocat/repo.git?x=1").is_err());
        assert!(validate_github_https_url("https://github.com/octocat/repo.git#frag").is_err());
        assert!(validate_github_https_url("https://github.com/octocat/../evil").is_err());
        assert!(validate_github_https_url("https://github.com/octocat/repo\n").is_err());
        assert!(validate_github_https_url("https://github.com/octocat").is_err());
        assert!(validate_github_https_url("https://github.com/octocat/repo/extra").is_err());
    }

    #[test]
    fn test_validate_repo_name() {
        assert_eq!(validate_repo_name(" gitolorin ").unwrap(), "gitolorin");
        assert!(validate_repo_name("my-repo_01.rs").is_ok());
        assert!(validate_repo_name("").is_err());
        assert!(validate_repo_name("-leading-dash").is_err());
        assert!(validate_repo_name(".hidden").is_err());
        assert!(validate_repo_name("foo..bar").is_err());
        assert!(validate_repo_name("foo/bar").is_err());
        assert!(validate_repo_name(&"a".repeat(101)).is_err());
    }

    #[test]
    fn test_redact_secret_and_validate_token() {
        let tok = "ghp_ExampleSecretToken123456";
        assert_eq!(validate_token_for_header("  ghp_abc123  ").unwrap(), "ghp_abc123");
        assert!(validate_token_for_header("").is_err());
        assert!(validate_token_for_header("ghp_bad\nheader").is_err());
        assert!(validate_token_for_header("ghp_bad\"quote").is_err());

        let b64 = B64.encode(format!("x-access-token:{}", tok));
        let msg = format!("fatal: auth failed for {} / basic {}", tok, b64);
        let cleaned = redact_secret(&msg, tok);
        assert!(!cleaned.contains(tok));
        assert!(!cleaned.contains(&b64));
        assert!(cleaned.contains("[REDACTED]"));
    }
}
