use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcsToolStatus {
    pub git_installed: bool,
    pub git_version: String,
    pub jj_installed: bool,
    pub jj_version: String,
    pub jj_path: Option<String>,
}

pub fn check_vcs_tools(base_dir: &Path) -> VcsToolStatus {
    let git_out = Command::new("git").arg("--version").output().ok();
    let git_installed = git_out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let git_version = git_out
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let local_jj = base_dir.join("bin").join(if cfg!(windows) { "jj.exe" } else { "jj" });
    let jj_cmd = if local_jj.is_file() {
        local_jj.to_string_lossy().to_string()
    } else {
        "jj".to_string()
    };

    let jj_out = Command::new(&jj_cmd).arg("--version").output().ok();
    let jj_installed = jj_out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let jj_version = jj_out
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    VcsToolStatus {
        git_installed,
        git_version,
        jj_installed,
        jj_version,
        jj_path: if jj_installed { Some(jj_cmd) } else { None },
    }
}

/// Automatically downloads the official precompiled `jj` (Jujutsu) binary for the current OS/arch
/// into `~/.gitolorin/bin/jj` if it is not already installed on the machine.
pub async fn ensure_jj_installed(base_dir: &Path) -> Result<PathBuf> {
    let status = check_vcs_tools(base_dir);
    if let Some(existing) = status.jj_path {
        return Ok(PathBuf::from(existing));
    }

    let bin_dir = base_dir.join("bin");
    fs::create_dir_all(&bin_dir)?;

    let target_triple = if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "x86_64-unknown-linux-musl"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-musl"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        "x86_64-apple-darwin"
    } else {
        return Err(anyhow!(
            "Arquitectura no soportada para autodescarga de jj; instálalo con 'cargo install jj-cli'."
        ));
    };

    let version = "v0.23.0";
    let url = format!(
        "https://github.com/jj-vcs/jj/releases/download/{}/jj-{}-{}.tar.gz",
        version, version, target_triple
    );

    let archive_path = bin_dir.join("jj.tar.gz");
    let curl_st = Command::new("curl")
        .args(["-fsSL", &url, "-o", &archive_path.to_string_lossy()])
        .status()
        .context("Descargando binario oficial de Jujutsu (jj) con curl")?;

    if !curl_st.success() {
        return Err(anyhow!(
            "No se pudo descargar Jujutsu desde GitHub Releases ({})",
            url
        ));
    }

    let tar_status = Command::new("tar")
        .args(["-xzf", &archive_path.to_string_lossy(), "-C", &bin_dir.to_string_lossy(), "./jj"])
        .status()
        .or_else(|_| {
            Command::new("tar")
                .args(["-xzf", &archive_path.to_string_lossy(), "-C", &bin_dir.to_string_lossy()])
                .status()
        })?;

    let _ = fs::remove_file(&archive_path);
    if !tar_status.success() {
        return Err(anyhow!("Error extrayendo binario jj"));
    }

    let jj_bin = bin_dir.join("jj");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&jj_bin, fs::Permissions::from_mode(0o755));
    }

    Ok(jj_bin)
}

/// Generates or updates `AGENTS.md` in the target project root so any AI coding agent
/// (Claude Code, Antigravity, Cursor, Codex, Aider) automatically follows the chosen VCS workflow
/// and knows how to submit MRs to the gitOlorin queue without attempting forbidden direct pushes to `main`.
pub fn inject_agents_md(
    project_dir: &Path,
    repo_name: &str,
    vcs_mode: &str,
    proxy_remote_url: &str,
) -> Result<()> {
    let agents_path = project_dir.join("AGENTS.md");

    let vcs_instructions = match vcs_mode {
        "jj" => format!(
            r#"### Version Control Mode: **Jujutsu (`jj`) Colocated with Git**
- **Trabaja en este repositorio con Jujutsu (`jj`)** (ya inicializado en modo `--colocate` con `.jj` y `.git`).
- Cada modificación en el árbol de trabajo es automáticamente un commit/snapshot (no necesitas `git add`).
- Si un cambio o experimento sale mal, usa `jj undo` o `jj op restore` para revertir de forma atómica.
- Para publicar tus cambios en una rama de trabajo hacia el proxy `gitOlorin`:
  1. Crea o mueve un bookmark a tu cambio: `jj bookmark set feat/<descripcion> -r @`
  2. Empuja la rama de trabajo: `jj git push --bookmark feat/<descripcion> --allow-new`
- Para proponer que tus cambios pasen a `main`:
  - Ejecuta: `gitolorin mr create --repo {repo_name} --source feat/<descripcion> --target main --title "<Título>"`"#
        ),
        "worktree" => format!(
            r#"### Version Control Mode: **Git Worktrees (Árboles de Trabajo Paralelos)**
- **Trabaja en este repositorio usando ramas de trabajo aisladas y `git worktree`** cuando ejecutes subagentes en paralelo.
- Para crear un árbol de trabajo aislado para una subtarea:
  `git worktree add ../wt-{repo_name}-<tarea> -b agent/<tarea>`
- Haz commits incrementales y empuja siempre a tu rama `agent/<tarea>` o `feat/<tarea>`:
  `git push -u origin feat/<tarea>`
- Para proponer un Merge Request hacia `main`:
  `gitolorin mr create --repo {repo_name} --source feat/<tarea> --target main --title "<Título>"`"#
        ),
        _ => format!(
            r#"### Version Control Mode: **Git Estándar (Ramas de Trabajo Protegidas)**
- Trabaja siempre sobre ramas de funcionalidad o agente (`feat/*`, `fix/*`, `agent/*`).
- Empuja tus avances libremente a tu rama secundaria:
  `git push -u origin feat/<tarea>`
- Para proponer que tus cambios se fusionen a `main`:
  `gitolorin mr create --repo {repo_name} --source feat/<tarea> --target main --title "<Título>"`"#
        ),
    };

    let section = format!(
        r#"<!-- GITOLORIN-MANAGED-START -->
# 🧙‍♂️ gitOlorin — Reglas de Control de Versiones y Seguridad para Agentes IA

Este repositorio está protegido y gobernado por **gitOlorin** (Local Git Bastion & Biometric Approval Queue).
El remote `origin` (`{proxy_remote_url}`) apunta al proxy de seguridad local de `gitOlorin`.

{vcs_instructions}

### ⛔ Restricciones Estrictas ("You Shall Not Pass!")
1. **PROHIBIDO hacer push directo a `main` / `master`:** Cualquier push directo a `main` será interceptado por el proxy `gitOlorin` y retenido en la Cola de Aprobación Humana (requiere huella/PIN del propietario).
2. **PROHIBIDO `git push --force` o borrar ramas remotas:** La reescritura de historial remoto está bloqueada para agentes. Si necesitas corregir algo, añade un nuevo commit o crea una rama nueva.
3. **Cero exposición de credenciales:** No busques ni pidas tokens de GitHub (`ghp_...`). `gitOlorin` inyecta tokens efímeros de 1 solo repositorio automáticamente al hacer push a ramas `feat/*` o `agent/*`.
<!-- GITOLORIN-MANAGED-END -->
"#
    );

    if agents_path.is_file() {
        let existing = fs::read_to_string(&agents_path).unwrap_or_default();
        if let (Some(start), Some(end)) = (
            existing.find("<!-- GITOLORIN-MANAGED-START -->"),
            existing.find("<!-- GITOLORIN-MANAGED-END -->"),
        ) {
            let end_idx = end + "<!-- GITOLORIN-MANAGED-END -->".len();
            let mut updated = String::new();
            updated.push_str(&existing[..start]);
            updated.push_str(section.trim());
            updated.push_str(&existing[end_idx..]);
            fs::write(&agents_path, updated)?;
            return Ok(());
        } else {
            let combined = format!("{}\n\n{}", existing.trim_end(), section);
            fs::write(&agents_path, combined)?;
            return Ok(());
        }
    }

    fs::write(&agents_path, section)?;
    Ok(())
}
