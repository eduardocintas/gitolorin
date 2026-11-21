pub mod github;
pub mod inspector;
pub mod proxy;
pub mod queue;
pub mod vault;
pub mod vcs;

use crate::github::{execute_approved_queue_item, initialize_managed_repository};
use crate::inspector::compute_bare_diff_summary;
use crate::proxy::{build_router, AppState};
use crate::queue::{QueueItemKind, QueueItemStatus, StateStore};
use crate::vault::{AdminSecret, VaultManager};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "gitolorin",
    version = "0.1.0",
    about = "🧙‍♂️ gitOlorin — Local Git Bastion, Credential Broker & Biometric Approval Queue for AI Agents"
)]
struct Cli {
    /// Custom data directory (defaults to ~/.gitolorin)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Local proxy & web UI port
    #[arg(long, global = true, default_value_t = 9418)]
    port: u16,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the gitOlorin Local Git Smart HTTP Proxy + Web UI Server (default if no subcommand given)
    Serve {
        /// Automatically open the Web UI in the default browser
        #[arg(long)]
        open: bool,
    },
    /// Initialize or link a repository with gitOlorin proxy, scoped token, VCS tool (jj/git/worktree), and AGENTS.md
    Init {
        /// Repository name (e.g. my-project)
        name: String,
        /// Target workspace path (defaults to current directory or /home/edu/git/pub/<name>)
        #[arg(long)]
        path: Option<PathBuf>,
        /// Version control workflow to configure in AGENTS.md ("jj", "worktree", "git")
        #[arg(long, default_value = "jj")]
        vcs: String,
        /// Make the GitHub repository public instead of private
        #[arg(long)]
        public: bool,
        /// Interactive owner mode: unlock Admin Vault with OS Fingerprint/Biometrics and create on GitHub immediately
        #[arg(long)]
        bio: bool,
        /// Interactive owner mode: unlock Admin Vault with PIN and create on GitHub immediately
        #[arg(long)]
        pin: Option<String>,
    },
    /// Seal or update the AES-256-GCM + Argon2id Admin Vault from CLI
    SetupVault {
        #[arg(long)]
        github_user: String,
        #[arg(long)]
        admin_pat: String,
        #[arg(long, default_value = "")]
        worker_token: String,
        #[arg(long)]
        pin: String,
        #[arg(long, default_value_t = true)]
        os_bio: bool,
    },
    /// Enqueue a Merge Request (MR / PR) targeting main/master into the gitOlorin approval queue
    Mr {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "main")]
        target: String,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// View the current approval queue, managed repositories, and vault status
    Status,
    /// Approve and execute all ready/pending items in the queue with 1 OS Biometric Fingerprint or PIN
    Approve {
        /// Use OS native fingerprint / Polkit / TouchID / Windows Hello
        #[arg(long)]
        bio: bool,
        /// Unlock using vault PIN
        #[arg(long)]
        pin: Option<String>,
        /// Approve all pending items (even if not pre-marked in Web UI)
        #[arg(long)]
        all: bool,
    },
}

fn resolve_base_dir(custom: Option<PathBuf>) -> PathBuf {
    if let Some(p) = custom {
        return p;
    }
    if let Ok(env_p) = std::env::var("GITOLORIN_HOME") {
        return PathBuf::from(env_p);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".gitolorin")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let base_dir = resolve_base_dir(cli.data_dir);
    let vault = VaultManager::new(base_dir.clone())?;
    let store = StateStore::new(base_dir.clone())?;

    match cli.command.unwrap_or(Commands::Serve { open: false }) {
        Commands::Serve { open } => {
            let addr = format!("127.0.0.1:{}", cli.port);
            let url = format!("http://{}", addr);
            println!("🧙‍♂️ gitOlorin v0.1.0 — Local Git Bastion & Biometric Approval Queue");
            println!("   ├─ Web UI & Dashboard : {}", url);
            println!("   ├─ Git Smart Proxy    : {}/git/<repo>.git", url);
            println!("   └─ Datos y Staging    : {}", base_dir.display());

            if open {
                let _ = open_browser(&url);
            }

            let state = Arc::new(AppState {
                base_dir,
                port: cli.port,
                vault,
                store,
            });
            let app = build_router(state);
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }
        Commands::SetupVault {
            github_user,
            admin_pat,
            worker_token,
            pin,
            os_bio,
        } => {
            let secret = AdminSecret {
                github_username: github_user,
                admin_pat,
                worker_pat_or_app_token: worker_token,
            };
            vault.seal_vault(&secret, &pin, os_bio, None)?;
            println!("✅ Bóveda Admin sellada con AES-256-GCM + Argon2id en {}", vault.vault_path().display());
        }
        Commands::Init {
            name,
            path,
            vcs,
            public,
            bio,
            pin,
        } => {
            let wcfg = vault.load_worker_config();
            let ws_path = path.unwrap_or_else(|| {
                let pub_base = PathBuf::from("/home/edu/git/pub");
                if pub_base.is_dir() {
                    pub_base.join(&name)
                } else {
                    std::env::current_dir().unwrap().join(&name)
                }
            });

            let secret_opt = if bio {
                Some(vault.unseal_with_os_biometrics(&format!("gitOlorin: Crear repo {}", name))?)
            } else if let Some(p) = pin {
                Some(vault.unseal_with_pin(&p)?)
            } else {
                None
            };

            let res = initialize_managed_repository(
                &base_dir,
                &store,
                &name,
                &wcfg.github_username,
                &ws_path,
                !public,
                &vcs,
                cli.port,
                secret_opt.as_ref(),
            )
            .await?;

            println!("{}", res.message);
            println!("   ├─ Workspace : {}", res.repo.local_workspace_path);
            println!("   ├─ Staging   : {}", res.repo.bare_staging_path);
            println!("   └─ AGENTS.md : Configurado con modo '{}'", res.repo.vcs_mode);
        }
        Commands::Mr {
            repo,
            source,
            target,
            title,
            description,
        } => {
            let bare_path = store.staging_dir.join(format!("{}.git", repo));
            let diff_sum = compute_bare_diff_summary(
                &bare_path,
                &format!("refs/heads/{}", target),
                &format!("refs/heads/{}", source),
            )
            .unwrap_or_else(|_| "Diff pendiente".to_string());

            let wcfg = vault.load_worker_config();
            let item = store.enqueue_item(
                QueueItemKind::MergeRequest,
                repo.clone(),
                title.clone(),
                if description.is_empty() {
                    format!("Merge {} -> {}", source, target)
                } else {
                    description
                },
                source,
                target,
                crate::inspector::ZERO_SHA.to_string(),
                "HEAD".to_string(),
                true,
                wcfg.default_vcs,
                diff_sum,
            )?;
            println!(
                "📋 Merge Request #{} ('{}') encolado en gitOlorin para aprobación con Huella/PIN.",
                item.id, item.title
            );
        }
        Commands::Status => {
            let db = store.snapshot();
            let v_status = vault.get_public_status();
            println!("🧙‍♂️ gitOlorin — Estado de la Cola y Repositorios");
            println!(
                "   Bóveda Admin: {}",
                if v_status["initialized"].as_bool().unwrap_or(false) {
                    "✅ Encriptada y Sellada (AES-256-GCM)"
                } else {
                    "⚠️ Sin inicializar"
                }
            );
            println!("   Repositorios gobernados: {}", db.repos.len());
            println!("\n📋 COLA DE PENDIENTES:");
            let pending: Vec<_> = db
                .queue
                .iter()
                .filter(|q| {
                    matches!(
                        q.status,
                        QueueItemStatus::Pending | QueueItemStatus::ApprovedForBatch
                    )
                })
                .collect();
            if pending.is_empty() {
                println!("   (Vacía — Todo al día)");
            } else {
                for item in pending {
                    let mark = if item.status == QueueItemStatus::ApprovedForBatch {
                        "[☑️ LISTO]"
                    } else {
                        "[⏳ PENDIENTE]"
                    };
                    println!(
                        "   #{} {} {:?} en '{}' | {} ({} -> {})",
                        item.id,
                        mark,
                        item.kind,
                        item.repo_name,
                        item.title,
                        item.source_branch,
                        item.target_branch
                    );
                }
            }
        }
        Commands::Approve { bio, pin, all } => {
            let secret = if bio {
                vault.unseal_with_os_biometrics("gitOlorin: Aprobar lote de cola")?
            } else if let Some(p) = pin {
                vault.unseal_with_pin(&p)?
            } else {
                return Err(anyhow::anyhow!(
                    "Debes especificar --bio (Huella del sistema) o --pin <PIN> para desbloquear la bóveda."
                ));
            };

            let db = store.snapshot();
            let targets: Vec<_> = db
                .queue
                .into_iter()
                .filter(|q| {
                    if all {
                        matches!(
                            q.status,
                            QueueItemStatus::Pending | QueueItemStatus::ApprovedForBatch
                        )
                    } else {
                        q.status == QueueItemStatus::ApprovedForBatch
                    }
                })
                .collect();

            if targets.is_empty() {
                println!("No hay ítems marcados para aprobar (usa --all para aprobar todos los pendientes).");
                return Ok(());
            }

            for item in targets {
                match execute_approved_queue_item(&store, &item, &secret).await {
                    Ok(msg) => println!("✅ #{}: {}", item.id, msg),
                    Err(e) => println!("❌ #{}: Error: {}", item.id, e),
                }
            }
            drop(secret);
            println!("🔒 Lote completado y llave Admin borrada de la RAM (ZeroizeOnDrop).");
        }
    }

    Ok(())
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn();
    }
    Ok(())
}
