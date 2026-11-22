---
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
- **NEVER rewrite a commit already pushed to a remote bookmark** (no `jj describe`, `jj squash`, or `jj rebase` on pushed commits); always create a new change on top with `jj new` so pushes stay fast-forward.
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
