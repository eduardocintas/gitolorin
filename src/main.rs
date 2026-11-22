pub mod autostart;
pub mod github;
pub mod inspector;
pub mod proxy;
pub mod queue;
pub mod templates;
pub mod tray;
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
        /// Disable the native System Tray icon
        #[arg(long)]
        no_tray: bool,
    },
    /// Launch gitOlorin as a standalone frameless desktop App window (starts background daemon if needed)
    App,
    /// Install desktop menu entry & icon on Linux (~/.local/share/applications/gitolorin.desktop)
    InstallDesktop,
    /// Manage cross-platform OS autostart (`enable`, `disable`, or `status`)
    Autostart {
        /// Action: enable | disable | status
        action: String,
    },
    /// Initialize or link a repository with gitOlorin proxy, scoped token, VCS tool (jj/git/worktree), and AGENTS.md
    Init {
        /// Repository name (e.g. my-project)
        name: String,
        /// Long display name / GitHub description (e.g. "Just Make My Desktop Mine")
        #[arg(long, default_value = "")]
        display_name: String,
        /// Starter project template ID (e.g. "empty", "rust-web-app")
        #[arg(long, default_value = "empty")]
        template: String,
        /// Open-source license to generate (`MIT`, `Apache-2.0`, `GPL-3.0-or-later`, `none`)
        #[arg(long, default_value = "MIT")]
        license: String,
        /// Initialize locally without queuing a GitHub repo creation
        #[arg(long)]
        local_only: bool,
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
    let base_dir_arg = cli.data_dir.clone();
    let base_dir = resolve_base_dir(cli.data_dir);
    let _ = templates::ensure_builtin_templates(&base_dir);
    let _ = vcs::ensure_gitolorin_skill_installed();
    let vault = VaultManager::new(base_dir.clone())?;
    let store = StateStore::new(base_dir.clone())?;

    match cli.command.unwrap_or(Commands::Serve { open: false, no_tray: false }) {
        Commands::Serve { open, no_tray } => {
            let addr = format!("127.0.0.1:{}", cli.port);
            let url = format!("http://gitolorin.localhost:{}", cli.port);
            println!("🧙‍♂️ gitOlorin v0.1.0 — Local Git Bastion & Biometric Approval Queue");
            println!("   ├─ Web UI & Dashboard : {}", url);
            println!("   ├─ Git Smart Proxy    : http://127.0.0.1:{}/git/<repo>.git", cli.port);
            println!("   └─ Datos y Staging    : {}", base_dir.display());

            if open {
                let _ = open_browser(&url);
            }

            let state = Arc::new(AppState {
                base_dir: base_dir.clone(),
                port: cli.port,
                vault,
                store,
            });

            if !no_tray {
                let url_for_tray = url.clone();
                let base_for_tray = base_dir.clone();
                tray::spawn_tray(
                    Arc::clone(&state),
                    cli.port,
                    Arc::new(move || {
                        let _ = open_app_window(&url_for_tray, &base_for_tray);
                    }),
                );
            }

            let app = build_router(state);
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            if let Ok(v6_listener) =
                tokio::net::TcpListener::bind(format!("[::1]:{}", cli.port)).await
            {
                let app_v6 = app.clone();
                tokio::spawn(async move {
                    let _ = axum::serve(v6_listener, app_v6).await;
                });
            }
            axum::serve(listener, app).await?;
        }
        Commands::App => {
            let addr_sock: std::net::SocketAddr = format!("127.0.0.1:{}", cli.port).parse()?;
            let is_running = std::net::TcpStream::connect_timeout(
                &addr_sock,
                std::time::Duration::from_millis(250),
            )
            .is_ok();

            if !is_running {
                let exe = std::env::current_exe()?;
                let mut cmd = std::process::Command::new(exe);
                if let Some(ref d) = base_dir_arg {
                    cmd.arg("--data-dir").arg(d);
                }
                cmd.arg("--port")
                    .arg(cli.port.to_string())
                    .arg("serve")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                #[cfg(unix)]
                {
                    use std::os::unix::process::CommandExt;
                    cmd.process_group(0);
                }
                let _ = cmd.spawn()?;

                for _ in 0..30 {
                    if std::net::TcpStream::connect_timeout(
                        &addr_sock,
                        std::time::Duration::from_millis(100),
                    )
                    .is_ok()
                    {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }

            let url = format!("http://gitolorin.localhost:{}", cli.port);
            open_app_window(&url, &base_dir)?;
            println!("gitOlorin App abierta en {}", url);
        }
        Commands::InstallDesktop => {
            install_desktop_entry()?;
        }
        Commands::Autostart { action } => {
            match action.trim().to_lowercase().as_str() {
                "enable" | "on" | "1" => {
                    let msg = autostart::set_autostart(true)?;
                    println!("✅ {}", msg);
                }
                "disable" | "off" | "0" => {
                    let msg = autostart::set_autostart(false)?;
                    println!("✅ {}", msg);
                }
                _ => {
                    let enabled = autostart::is_autostart_enabled();
                    println!(
                        "⚡ Inicio automático: {}",
                        if enabled { "✅ Activado" } else { "Desactivado" }
                    );
                }
            }
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
            display_name,
            template,
            license,
            local_only,
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
                &display_name,
                &template,
                &license,
                &wcfg.github_username,
                &ws_path,
                !public,
                &vcs,
                cli.port,
                secret_opt.as_ref(),
                local_only,
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

fn open_app_window(url: &str, base_dir: &std::path::Path) -> Result<()> {
    let app_arg = format!("--app={}", url);
    let profile_dir = base_dir.join("webapp-profile");
    let _ = std::fs::create_dir_all(&profile_dir);
    let profile_arg = format!("--user-data-dir={}", profile_dir.display());
    let profile_str = profile_dir.to_string_lossy().to_string();

    #[cfg(target_os = "linux")]
    {
        // Single-instance check: if an app window using this isolated profile is already open,
        // focus it instead of spawning a duplicate window.
        if let Ok(out) = std::process::Command::new("pgrep")
            .args(["-f", &profile_str])
            .output()
        {
            if out.status.success() && !out.stdout.is_empty() {
                let _ = std::process::Command::new("wmctrl")
                    .args(["-a", "gitOlorin"])
                    .status();
                let _ = std::process::Command::new("xdotool")
                    .args(["search", "--name", "gitOlorin", "windowactivate"])
                    .status();
                return Ok(());
            }
        }

        let candidates = [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "brave-browser",
            "microsoft-edge",
        ];
        for bin in candidates {
            if let Ok(child) = std::process::Command::new(bin)
                .args([
                    &app_arg,
                    &profile_arg,
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-background-mode",
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                drop(child);
                return Ok(());
            }
        }
        return open_browser(url);
    }

    #[cfg(target_os = "macos")]
    {
        let _ = &profile_str;
        let apps = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ];
        for bin in apps {
            if std::path::Path::new(bin).is_file() {
                if std::process::Command::new(bin)
                    .args([&app_arg, &profile_arg, "--no-first-run"])
                    .spawn()
                    .is_ok()
                {
                    return Ok(());
                }
            }
        }
        return open_browser(url);
    }

    #[cfg(target_os = "windows")]
    {
        let _ = &profile_str;
        for bin in ["msedge", "chrome"] {
            if std::process::Command::new(bin)
                .args([&app_arg, &profile_arg, "--no-first-run"])
                .spawn()
                .is_ok()
            {
                return Ok(());
            }
        }
        return open_browser(url);
    }

    #[allow(unreachable_code)]
    Ok(())
}

fn install_desktop_entry() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let data_home = std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".local/share"));

        let icon_dir = data_home.join("icons/hicolor/512x512/apps");
        let apps_dir = data_home.join("applications");
        std::fs::create_dir_all(&icon_dir)?;
        std::fs::create_dir_all(&apps_dir)?;

        let icon_path = icon_dir.join("gitolorin.png");
        std::fs::write(&icon_path, include_bytes!("../static/icon-512.png"))?;

        let exe_path = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("/home/edu/.local/bin/gitolorin"));
        let desktop_path = apps_dir.join("gitolorin.desktop");
        let desktop_content = format!(
            "[Desktop Entry]\n\
            Version=1.0\n\
            Type=Application\n\
            Name=gitOlorin\n\
            Comment=Local Git Bastion & Biometric Approval Queue for AI Agents\n\
            Exec={} app\n\
            Icon={}\n\
            Terminal=false\n\
            StartupNotify=true\n\
            StartupWMClass=chrome-gitolorin.localhost__-Default\n\
            Categories=Development;Security;\n",
            exe_path.display(),
            icon_path.display()
        );
        std::fs::write(&desktop_path, desktop_content)?;
        println!("✅ Entrada de escritorio instalada en {}", desktop_path.display());
        println!("   └─ Icono PNG instalado en {}", icon_path.display());
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("ℹ️ install-desktop está pensado para menús de escritorio XDG en Linux.");
    }
    Ok(())
}
