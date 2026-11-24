use anyhow::{anyhow, Result};
use std::fs;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
fn linux_autostart_path() -> PathBuf {
    let cfg_home = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config")
        });
    cfg_home.join("autostart").join("gitolorin.desktop")
}

#[cfg(target_os = "macos")]
fn macos_plist_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/LaunchAgents/com.gitolorin.daemon.plist")
}

pub fn is_autostart_enabled() -> bool {
    #[cfg(target_os = "linux")]
    {
        return linux_autostart_path().is_file();
    }
    #[cfg(target_os = "macos")]
    {
        return macos_plist_path().is_file();
    }
    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("reg")
            .args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "gitOlorin",
            ])
            .output();
        return out.map(|o| o.status.success()).unwrap_or(false);
    }
    #[allow(unreachable_code)]
    false
}

pub fn set_autostart(enabled: bool) -> Result<String> {
    let exe_path = std::env::current_exe().unwrap_or_else(|_| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local/bin/gitolorin")
    });

    #[cfg(target_os = "linux")]
    {
        let path = linux_autostart_path();
        if enabled {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let data_home = std::env::var("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    dirs::home_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join(".local/share")
                });
            let icon_path = data_home.join("icons/hicolor/512x512/apps/gitolorin.png");
            let content = format!(
                "[Desktop Entry]\n\
                Version=1.0\n\
                Type=Application\n\
                Name=gitOlorin\n\
                Comment=Local Git Bastion & Biometric Approval Queue for AI Agents\n\
                Exec={} serve\n\
                Icon={}\n\
                Terminal=false\n\
                X-GNOME-Autostart-enabled=true\n\
                Categories=Development;Security;\n",
                exe_path.display(),
                icon_path.display()
            );
            fs::write(&path, content)?;
            return Ok(format!("Inicio automático activado en {}", path.display()));
        } else {
            if path.is_file() {
                fs::remove_file(&path)?;
            }
            return Ok("Inicio automático desactivado.".to_string());
        }
    }

    #[cfg(target_os = "macos")]
    {
        let path = macos_plist_path();
        if enabled {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.gitolorin.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>serve</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
"#,
                exe_path.display()
            );
            fs::write(&path, plist)?;
            return Ok(format!("Inicio automático activado en {}", path.display()));
        } else {
            if path.is_file() {
                fs::remove_file(&path)?;
            }
            return Ok("Inicio automático desactivado.".to_string());
        }
    }

    #[cfg(target_os = "windows")]
    {
        if enabled {
            let cmd_val = format!("\"{}\" serve", exe_path.display());
            let st = std::process::Command::new("reg")
                .args([
                    "add",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    "gitOlorin",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &cmd_val,
                    "/f",
                ])
                .status()?;
            if !st.success() {
                return Err(anyhow!("Error registrando autostart en el Registro de Windows."));
            }
            return Ok("Inicio automático activado en el Registro de Windows.".to_string());
        } else {
            let _ = std::process::Command::new("reg")
                .args([
                    "delete",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    "gitOlorin",
                    "/f",
                ])
                .status();
            return Ok("Inicio automático desactivado.".to_string());
        }
    }

    #[allow(unreachable_code)]
    Err(anyhow!("Plataforma no soportada para autostart"))
}
