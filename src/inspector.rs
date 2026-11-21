use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

pub const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRefUpdate {
    pub old_sha: String,
    pub new_sha: String,
    pub ref_name: String, // e.g., "refs/heads/main" or "refs/heads/feat/login"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PushVerdictKind {
    /// Clean fast-forward or new branch creation on a non-protected branch (e.g., feat/*, agent/*)
    AllowedFastForward,
    /// Direct push to a protected branch (main, master, production, etc.)
    BlockedProtectedBranch { branch: String },
    /// Force-push (non-fast-forward history rewrite) on an existing branch
    BlockedForcePush { branch: String, lost_commits: String },
    /// Branch or tag deletion (`new_sha == 0000...`)
    BlockedRefDeletion { ref_name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushInspectionResult {
    pub updates: Vec<GitRefUpdate>,
    pub verdict: PushVerdictKind,
    pub allowed: bool,
    pub human_reason: String,
}

/// Parses the pkt-line header section of a `git-receive-pack` HTTP POST request body.
/// Each command line in `git-receive-pack` before `0000` (flush-pkt) has the form:
/// `<4-hex-byte-length><old-sha> <new-sha> <ref-name>[\0<capabilities>]\n`
pub fn parse_receive_pack_commands(body: &[u8]) -> Vec<GitRefUpdate> {
    let mut updates = Vec::new();
    let mut offset = 0usize;

    while offset + 4 <= body.len() {
        let len_hex = match std::str::from_utf8(&body[offset..offset + 4]) {
            Ok(s) => s,
            Err(_) => break,
        };
        let pkt_len = match usize::from_str_radix(len_hex, 16) {
            Ok(l) => l,
            Err(_) => break,
        };

        // 0000 is the flush packet marking the end of ref update commands and start of PACK data
        if pkt_len == 0 {
            break;
        }
        if pkt_len < 4 || offset + pkt_len > body.len() {
            break;
        }

        let payload = &body[offset + 4..offset + pkt_len];
        offset += pkt_len;

        // Strip trailing NUL capabilities if present on the first command line
        let cmd_slice = match payload.iter().position(|&b| b == 0) {
            Some(nul_pos) => &payload[..nul_pos],
            None => payload,
        };

        if let Ok(line_str) = std::str::from_utf8(cmd_slice) {
            let trimmed = line_str.trim();
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 3 && parts[0].len() == 40 && parts[1].len() == 40 {
                updates.push(GitRefUpdate {
                    old_sha: parts[0].to_string(),
                    new_sha: parts[1].to_string(),
                    ref_name: parts[2].to_string(),
                });
            }
        }
    }

    updates
}

/// Checks if `old_sha` is an ancestor of `new_sha` inside the bare repository.
/// note: During pre-receive or before unpacking, if `new_sha` isn't unpacked yet,
/// we also check if `old_sha == ZERO_SHA` (new branch creation, always safe).
pub fn evaluate_push_updates(
    bare_repo_path: &Path,
    updates: &[GitRefUpdate],
    protected_branches: &[String],
) -> PushInspectionResult {
    for u in updates {
        let short_branch = u
            .ref_name
            .strip_prefix("refs/heads/")
            .unwrap_or(&u.ref_name)
            .to_string();

        // 1. Check for branch or tag deletion
        if u.new_sha == ZERO_SHA {
            return PushInspectionResult {
                updates: updates.to_vec(),
                verdict: PushVerdictKind::BlockedRefDeletion {
                    ref_name: u.ref_name.clone(),
                },
                allowed: false,
                human_reason: format!(
                    "🧙‍♂️ [gitOlorin: YOU SHALL NOT PASS!] El borrado de la rama/ref remota '{}' está bloqueado para agentes y se ha enviado a la Cola de Aprobación Humana.",
                    u.ref_name
                ),
            };
        }

        // 2. Check if target is a protected branch (e.g. main, master)
        let is_protected = protected_branches
            .iter()
            .any(|b| b.eq_ignore_ascii_case(&short_branch));

        if is_protected {
            return PushInspectionResult {
                updates: updates.to_vec(),
                verdict: PushVerdictKind::BlockedProtectedBranch {
                    branch: short_branch.clone(),
                },
                allowed: false,
                human_reason: format!(
                    "🧙‍♂️ [gitOlorin: YOU SHALL NOT PASS!] Push directo a la rama protegida '{}' interceptado. Los commits fueron guardados en la Cola de MRs para aprobación con tu Huella/PIN.",
                    short_branch
                ),
            };
        }

        // 3. Check if existing branch is being force-pushed (non-fast-forward)
        // Note: When inspected post-unpack inside our staging bare repo or via pre-receive hook,
        // if old_sha != ZERO_SHA and git merge-base --is-ancestor old_sha new_sha fails, it's a force push.
        if u.old_sha != ZERO_SHA && bare_repo_path.is_dir() {
            // Only check ancestry if new_sha already exists in the object db
            let has_new_obj = Command::new("git")
                .arg("--git-dir")
                .arg(bare_repo_path)
                .args(["cat-file", "-e", &u.new_sha])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            if has_new_obj {
                let is_ff = Command::new("git")
                    .arg("--git-dir")
                    .arg(bare_repo_path)
                    .args(["merge-base", "--is-ancestor", &u.old_sha, &u.new_sha])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(true);

                if !is_ff {
                    let lost = Command::new("git")
                        .arg("--git-dir")
                        .arg(bare_repo_path)
                        .args([
                            "log",
                            "--oneline",
                            &format!("{}..{}", u.new_sha, u.old_sha),
                        ])
                        .output()
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .unwrap_or_default();

                    return PushInspectionResult {
                        updates: updates.to_vec(),
                        verdict: PushVerdictKind::BlockedForcePush {
                            branch: short_branch.clone(),
                            lost_commits: lost,
                        },
                        allowed: false,
                        human_reason: format!(
                            "🧙‍♂️ [gitOlorin: YOU SHALL NOT PASS!] Force-push (reescritura de historial) detectado en '{}'. Retenido en la Cola de Aprobación Humana.",
                            short_branch
                        ),
                    };
                }
            }
        }
    }

    PushInspectionResult {
        updates: updates.to_vec(),
        verdict: PushVerdictKind::AllowedFastForward,
        allowed: true,
        human_reason: "Push seguro (fast-forward en rama de trabajo).".to_string(),
    }
}

/// Formats a Git Smart HTTP pkt-line error response so `git push` or `jj git push`
/// displays a clear, structured message in the agent's terminal without crashing Git.
pub fn build_git_receive_pack_rejection(ref_name: &str, message: &str) -> Vec<u8> {
    fn pkt_line(data: &[u8]) -> Vec<u8> {
        let len = data.len() + 4;
        let mut out = format!("{:04x}", len).into_bytes();
        out.extend_from_slice(data);
        out
    }

    let mut response = Vec::new();
    // Sideband-64k channel 2 (stderr message displayed as `remote: ...`)
    for line in message.lines() {
        let mut sb = vec![2u8];
        sb.extend_from_slice(format!("{}\n", line).as_bytes());
        response.extend_from_slice(&pkt_line(&sb));
    }

    // Channel 1 status report: unpack ok + ng <ref> <reason>
    let mut inner_report = Vec::new();
    inner_report.extend_from_slice(&pkt_line(b"unpack ok\n"));
    let ng_line = format!("ng {} blocked by gitOlorin policy (queued for human approval)\n", ref_name);
    inner_report.extend_from_slice(&pkt_line(ng_line.as_bytes()));
    inner_report.extend_from_slice(b"0000");

    let mut sb1 = vec![1u8];
    sb1.extend_from_slice(&inner_report);
    response.extend_from_slice(&pkt_line(&sb1));
    response.extend_from_slice(b"0000");
    response
}

/// Computes a human-readable diff stat between two refs or commits inside a bare repo
pub fn compute_bare_diff_summary(bare_repo_path: &Path, base_ref: &str, head_ref: &str) -> Result<String> {
    let base_exists = Command::new("git")
        .arg("--git-dir")
        .arg(bare_repo_path)
        .args(["rev-parse", "--verify", base_ref])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !base_exists {
        let out = Command::new("git")
            .arg("--git-dir")
            .arg(bare_repo_path)
            .args(["log", "--stat", "--oneline", "-n", "5", head_ref])
            .output()?;
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }

    let out = Command::new("git")
        .arg("--git-dir")
        .arg(bare_repo_path)
        .args([
            "diff",
            "--stat",
            &format!("{}...{}", base_ref, head_ref),
        ])
        .output()?;
    let stat = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let log_out = Command::new("git")
        .arg("--git-dir")
        .arg(bare_repo_path)
        .args([
            "log",
            "--oneline",
            &format!("{}..{}", base_ref, head_ref),
        ])
        .output()?;
    let commits = String::from_utf8_lossy(&log_out.stdout).trim().to_string();

    if commits.is_empty() && stat.is_empty() {
        return Ok("Sin cambios pendientes respecto a la rama destino.".to_string());
    }
    Ok(format!("Commits:\n{}\n\nArchivos:\n{}", commits, stat))
}

/// Install a native Git `pre-receive` hook into our bare staging repository so that even after
/// `git-receive-pack` unpacks incoming objects, any non-fast-forward (force-push) is caught
/// deterministically by Git itself if not explicitly bypassed by human approval.
pub fn install_staging_pre_receive_hook(bare_repo_path: &Path) -> Result<()> {
    let hooks_dir = bare_repo_path.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    let hook_path = hooks_dir.join("pre-receive");
    let script = r#"#!/usr/bin/env bash
# gitOlorin Bare Staging Guard Hook
if [ "${GITOLORIN_ADMIN_OVERRIDE:-0}" = "1" ]; then
  exit 0
fi

ZERO="0000000000000000000000000000000000000000"
while read -r oldrev newrev refname; do
  if [ "$newrev" = "$ZERO" ]; then
    echo "🧙‍♂️ [gitOlorin] YOU SHALL NOT PASS: Remote branch/tag deletion ($refname) requires human biometric approval." >&2
    exit 1
  fi
  if [ "$oldrev" != "$ZERO" ]; then
    if ! git merge-base --is-ancestor "$oldrev" "$newrev" 2>/dev/null; then
      echo "🧙‍♂️ [gitOlorin] YOU SHALL NOT PASS: Force-push (non-fast-forward) on $refname is forbidden for agents." >&2
      exit 1
    fi
  fi
done
exit 0
"#;
    std::fs::write(&hook_path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
