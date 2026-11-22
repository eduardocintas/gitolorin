use crate::inspector::{
     compute_bare_diff_summary, install_staging_pre_receive_hook,
};
use crate::queue::{ManagedRepo, QueueItem, QueueItemKind, QueueItemStatus, StateStore};
use crate::vault::AdminSecret;
use crate::vcs::{ensure_jj_installed, inject_agents_md};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    let clean_name = repo_name.trim();
    if clean_name.is_empty()
        || !clean_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(anyhow!(
            "Nombre de repositorio inválido '{}'. Usa solo letras, números, guiones o puntos.",
            clean_name
        ));
    }

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

    let out = Command::new("curl")
        .args([
            "-sS",
            "-X",
            "POST",
            "https://api.github.com/user/repos",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            &format!("Authorization: Bearer {}", secret.admin_pat.trim()),
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            "-H",
            "User-Agent: gitolorin/0.1.0",
            "-d",
            &payload,
        ])
        .output()
        .context("Llamando a GitHub API POST /user/repos")?;

    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();

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
        err_msg
    ))
}

/// Pushes a specific branch from our local bare staging repository to GitHub using an ephemeral
/// in-memory HTTP extraheader so the token is never written to `.git/config` or disk.
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

    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let basic = B64.encode(format!("x-access-token:{}", token.trim()));
    let auth_header = format!("AUTHORIZATION: basic {}", basic);
    let remote_url = format!("https://github.com/{}/{}.git", github_user, repo_name);

    let refspec = if branch_or_refspec.contains(':') || branch_or_refspec.starts_with("refs/") {
        branch_or_refspec.to_string()
    } else {
        format!("refs/heads/{}:refs/heads/{}", branch_or_refspec, branch_or_refspec)
    };

    let out = Command::new("git")
        .arg("--git-dir")
        .arg(bare_repo_path)
        .args([
            "-c",
            &format!("http.extraheader={}", auth_header),
            "push",
            &remote_url,
            &refspec,
        ])
        .output()
        .context("Sincronizando rama desde bare staging a GitHub")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("Error empujando a GitHub: {}", stderr.trim()));
    }
    Ok(())
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
                use base64::{engine::general_purpose::STANDARD as B64, Engine};
                let basic = B64.encode(format!("x-access-token:{}", secret.admin_pat.trim()));
                let auth_header = format!("AUTHORIZATION: basic {}", basic);
                let remote_url = format!("https://github.com/{}/{}.git", secret.github_username, item.repo_name);
                let _ = Command::new("git")
                    .arg("--git-dir")
                    .arg(&bare_path)
                    .args([
                        "-c",
                        &format!("http.extraheader={}", auth_header),
                        "push",
                        "--all",
                        &remote_url,
                    ])
                    .output();
            }
            store.mark_repo_synced(&item.repo_name, gh_url.clone())?;
            store.set_item_status(item.id, QueueItemStatus::Executed, None)?;
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
            let msg = format!(
                "Operación destructiva #{} aprobada y aplicada sobre '{}'.",
                item.id, target_ref
            );
            store.add_audit(&item.repo_name, "human-biometric", "approve_destructive_op", true, &msg);
            Ok(msg)
        }
    }
}
