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

pub fn ensure_jj_symlink(base_dir: &Path) {
    #[cfg(unix)]
    {
        let local_jj = base_dir.join("bin/jj");
        if local_jj.is_file() {
            if let Some(home) = dirs::home_dir() {
                let user_bin = home.join(".local/bin");
                let link_path = user_bin.join("jj");
                if link_path.symlink_metadata().is_err() {
                    let _ = fs::create_dir_all(&user_bin);
                    let _ = std::os::unix::fs::symlink(&local_jj, &link_path);
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = base_dir;
    }
}

/// Automatically downloads the official precompiled `jj` (Jujutsu) binary for the current OS/arch
/// into `~/.gitolorin/bin/jj` if it is not already installed on the machine.
pub async fn ensure_jj_installed(base_dir: &Path) -> Result<PathBuf> {
    let status = check_vcs_tools(base_dir);
    if let Some(existing) = status.jj_path {
        ensure_jj_symlink(base_dir);
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
    ensure_jj_symlink(base_dir);

    Ok(jj_bin)
}

pub const GITOLORIN_SKILL_MD: &str = r#"---
name: gitolorin
description: >-
  Rules and workflows for repositories governed by gitOlorin (Local Git Bastion & Biometric Approval Queue).
  Load this skill whenever working in a repo whose AGENTS.md says it is protected by gitOlorin.
---

# gitOlorin — Agent Workflow & Safety Rules ("You Shall Not Pass!")

Repositories governed by `gitOlorin` route `origin` through the local security proxy (`http://127.0.0.1:9418/git/<repo>.git`) with a per-repository token.

> **Prerequisite:** If `gitolorin` is not installed or running on this machine, install it from [github.com/eduardocintas/gitolorin](https://github.com/eduardocintas/gitolorin) and start it with `gitolorin app`.

## Strict Restrictions
1. **NEVER push directly to `main` / `master` / `production` / `release`:** Direct pushes are intercepted by `gitOlorin`, parked on a temporary ref, and queued for human biometric approval.
2. **NEVER run `git push --force` or delete remote branches/tags:** History rewriting on remote branches is blocked for agents. Add a new commit or create a new branch instead.
3. **NEVER search for or ask for GitHub PATs (`ghp_...`):** `gitOlorin` handles authentication transparently for feature branches.

## Workflow by VCS Mode

### 1. Jujutsu (`jj` colocated with Git)
- **`jj` is the primary VCS.** Use `jj status`, `jj log`, `jj diff`, `jj describe -m "..."`, and `jj new` for all checkpoints, atomic changes, and verification gates.
- If `jj` is not on `$PATH`, `gitOlorin` installs it at `~/.gitolorin/bin/jj` and symlinks `~/.local/bin/jj`.
- **NEVER use `git add`, `git commit`, or `git status` as workflow or gate checks** in a `jj` colocated repo (doing so breaks the expected `jj` working-copy & bookmark model).
- Every working-tree edit is automatically tracked as a snapshot (no `git add` required).
- If an experiment goes wrong, roll back atomically with `jj undo` or `jj op restore`.
- Describe your change, advance to a new working-copy change, and push a feature bookmark:
  ```bash
  jj status
  jj describe -m "feat: concise summary"
  jj new
  jj bookmark set feat/<task> -r @-
  jj git push --bookmark feat/<task>
  ```

### 2. Git Worktrees (`worktree`)
- Use isolated worktrees for parallel subagents without colliding on the same working directory:
  ```bash
  git worktree add ../wt-<repo>-<task> -b agent/<task>
  ```
- Commit and push to your `agent/<task>` or `feat/<task>` branch:
  ```bash
  git push -u origin feat/<task>
  ```

### 3. Standard Git (`git`)
- Always work on feature/agent branches (`feat/*`, `fix/*`, `agent/*`):
  ```bash
  git checkout -b feat/<task>
  git push -u origin feat/<task>
  ```

## Proposing Changes to `main` (Merge Request Queue)
Once your feature branch is pushed, enqueue a Merge Request for human review and 1-fingerprint batch approval *(Exact subcommand is `gitolorin mr`, NOT `gitolorin mr create`.)*:
```bash
gitolorin mr --repo <repo> --source feat/<task> --target main --title "<Title>"
```
"#;

/// Installs or updates the global `gitolorin` agent skill (`SKILL.md`) for Progressive Disclosure
/// in `~/.gemini/config/skills/gitolorin/SKILL.md` and `~/.agents/skills/gitolorin/SKILL.md`.
pub fn ensure_gitolorin_skill_installed() -> Result<()> {
    if let Some(home) = dirs::home_dir() {
        for rel in [
            ".gemini/config/skills/gitolorin/SKILL.md",
            ".agents/skills/gitolorin/SKILL.md",
        ] {
            let p = home.join(rel);
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&p, GITOLORIN_SKILL_MD);
        }
    }
    Ok(())
}

/// Generates or updates `AGENTS.md` and `.agents/skills/gitolorin/SKILL.md` in the target project root
/// using Progressive Disclosure: keeps `AGENTS.md` to a single concise line referencing the local skill.
pub fn inject_agents_md(
    project_dir: &Path,
    repo_name: &str,
    vcs_mode: &str,
    _proxy_remote_url: &str,
) -> Result<()> {
    let _ = ensure_gitolorin_skill_installed();

    let local_skill_path = project_dir.join(".agents/skills/gitolorin/SKILL.md");
    if let Some(parent) = local_skill_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&local_skill_path, GITOLORIN_SKILL_MD)?;

    let agents_path = project_dir.join("AGENTS.md");

    let (vcs_hint, vcs_short) = match vcs_mode {
        "jj" => ("jj colocated — use jj, NOT git commit/status", "jj"),
        "worktree" => ("git worktree", "worktree"),
        _ => ("git (feature branches)", "git"),
    };

    let section = format!(
        "<!-- GITOLORIN-MANAGED-START -->\n> **You shall not pass!** This repo (`{}`) is protected by **gitOlorin** (VCS: `{}`). See skill `gitolorin` (`.agents/skills/gitolorin/SKILL.md`) for commit, push, `{}`, and MR rules.\n<!-- GITOLORIN-MANAGED-END -->\n",
        repo_name, vcs_hint, vcs_short
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
