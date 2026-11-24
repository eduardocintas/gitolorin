# <img src="static/icon-192.png" width="48" align="absmiddle" alt="gitOlorin" /> gitOlorin

**Local Git Bastion, Credential Broker & Biometric Approval Queue for AI Coding Agents.**  
*("You Shall Not Pass!" for `main`, `master`, `--force`, and destructive Git operations)*

---

## The Problem

When working with AI coding agents (Claude Code, Antigravity, Cursor, Codex, Aider):

1. **GitHub Setup Friction:** Creating a new repository on GitHub, configuring branch rules, and manually clicking through the web UI to generate a *Fine-Grained PAT* (which GitHub does not allow creating via API) adds minutes of friction to every new project.
2. **Free-Tier Private Repo Gap:** GitHub Free does not support Branch Rulesets or branch protection on private repositories.
3. **Owner Token Exposure & Prompt Injection:** Handing a personal access token or `gh` session directly to an agent means a hallucination or indirect prompt injection can run `git push --force origin main`, rewrite history, or delete remote branches.

---

## How `gitOlorin` Solves It

`gitOlorin` is a portable, single-binary Rust application (API server, Git Smart HTTP proxy, embedded Web UI, and native System Tray) that acts as the **single bastion between your AI agents and GitHub**:

1. **Dual-Credential Model & Biometric Vault (`AES-256-GCM` + `Argon2id` + `Zeroize`):**
   - **Worker Credential (Low Privilege — Optional):** Encrypted inside the Admin Vault (never stored in plaintext on disk) and cached strictly in RAM while the server runs for clean *fast-forward* pushes to secondary feature branches (`feat/*`, `agent/*`).
   - **Admin Vault (High Privilege):** Stored encrypted in `~/.gitolorin/admin.vault` (`0600`). **Never decrypted in RAM while agents work.** The optional OS biometric unseal key is isolated outside the user's writable directory (Linux root-only `/etc/gitolorin/` via Polkit `pkexec`, macOS Keychain, Windows DPAPI) so local processes cannot unwrap it without OS authentication, and `AdminSecret` is wiped from memory immediately via `Zeroize`.
   - **API & Transport Hardening:** Web UI API endpoints enforce `Host` allowlisting, `Origin` / `Sec-Fetch-Site` checks, and `HttpOnly; SameSite=Strict` session cookies; GitHub tokens are passed only via `stdin` (`curl --config -`) or host-scoped `GIT_CONFIG_*` environment variables (never in `argv` or shell history) and only to validated `https://github.com/` URLs.
2. **Instant Local Staging (Zero Blocking):**
   - When an agent proactively requests a new repository (`gitolorin init my-repo`), `gitOlorin` immediately creates a local bare staging repository in `~/.gitolorin/staging/my-repo.git`, assigns a per-project local proxy token, and queues `CreateRepo` for your review.
   - The agent can commit, branch, and `git push` immediately without waiting for you—even offline.
3. **Automatic `AGENTS.md` Injection + Jujutsu (`jj`) / Git Worktrees:**
   - During `init`, `gitOlorin` automatically checks/downloads **Jujutsu (`jj`)** (or sets up `git worktree`), configures `origin` to point to the local proxy, and injects workflow & safety rules into `AGENTS.md`.
4. **Git Protocol-Level Gatekeeper (`git-receive-pack`):**
   - If an agent attempts `git push origin main`, `git push --force`, or remote branch deletion, `gitOlorin` intercepts it (*"YOU SHALL NOT PASS!"*), safely parks the commits on a temporary ref (`olorin-parked-*` / `olorin-force-*`), sends a desktop notification, and adds it to your **Approval Queue**.
5. **Batch Review ("One Fingerprint & Done"):**
   - Whenever you have a moment, open the standalone app (`gitolorin app` or via the **System Tray** icon, ~8.5 MB RAM), inspect the diffs, mark what you want, and approve the entire batch (repo creations + merges to `main`) with **one single Fingerprint or PIN**.

---

## Quick Start

```bash
# 1. Open the standalone desktop App window & start background proxy + System Tray
gitolorin app

# (Optional on Linux) Install application menu shortcut & icon
gitolorin install-desktop

# 2. Configure your encrypted Admin Vault (prompts securely without exposing secrets in shell history)
gitolorin setup-vault --github-user <your-user> --os-bio

# 3. Initialize a repository (Agent / Local Staging mode + Jujutsu in AGENTS.md)
gitolorin init my-project --vcs jj

# 4. Initialize a repository (Interactive Owner mode: unlock with fingerprint & create on GitHub now)
gitolorin init my-project --vcs jj --bio

# 5. Enqueue a Merge Request targeting main
gitolorin mr --repo my-project --source feat/login --target main --title "Implement OAuth2"

# 6. Inspect queue and approve everything in one batch with OS Fingerprint or PIN
gitolorin status
gitolorin approve --bio --all
```

---

## Cross-Platform Support

- **Linux:** Native D-Bus System Tray (`ksni`), Polkit/`fprintd` fingerprint unlock, `notify-send` alerts, and standalone Chromium/Chrome `--app` window.
- **macOS:** Native `tray-icon`, Touch ID / `osascript` prompt, and standalone browser app window.
- **Windows:** Native `tray-icon`, Windows Hello (`UserConsentVerifier`), and standalone Edge/Chrome `--app` window.

## License

[MIT](LICENSE)
