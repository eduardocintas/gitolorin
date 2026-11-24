use crate::vault::{set_dir_0700, write_file_0600};
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueueItemKind {
    /// Agent proactively requested a new repo; currently living in local staging bare repo, pending GitHub creation & sync
    CreateRepo,
    /// Agent opened a Merge Request / Pull Request targeting a protected branch (e.g. main/master)
    MergeRequest,
    /// Agent attempted a direct push to a protected branch (intercepted and parked on a staging ref)
    ProtectedBranchPush,
    /// Agent attempted a force-push (non-fast-forward history rewrite) or remote branch deletion
    DestructiveGitOp,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueueItemStatus {
    Pending,
    ApprovedForBatch,
    Rejected,
    Executed,
    Failed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QueueItem {
    pub id: u64,
    pub kind: QueueItemKind,
    pub status: QueueItemStatus,
    pub repo_name: String,
    pub title: String,
    pub description: String,
    pub source_branch: String,
    pub target_branch: String,
    pub old_sha: String,
    pub new_sha: String,
    pub private_repo: bool,
    pub vcs_mode: String,
    pub diff_summary: String,
    pub created_at: String,
    pub resolved_at: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ManagedRepo {
    pub name: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub template_id: String,
    pub owner: String,
    pub local_workspace_path: String,
    pub bare_staging_path: String,
    pub github_synced: bool,
    pub github_url: Option<String>,
    pub private: bool,
    pub vcs_mode: String, // "jj", "git", "worktree"
    /// Unique per-project local proxy token so an agent in repo A cannot push to repo B
    pub project_proxy_token: String,
    pub created_at: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct PublicManagedRepo {
    pub name: String,
    pub display_name: String,
    pub template_id: String,
    pub owner: String,
    pub local_workspace_path: String,
    pub bare_staging_path: String,
    pub github_synced: bool,
    pub github_url: Option<String>,
    pub private: bool,
    pub vcs_mode: String,
    pub created_at: String,
}

impl ManagedRepo {
    pub fn to_public(&self) -> PublicManagedRepo {
        PublicManagedRepo {
            name: self.name.clone(),
            display_name: self.display_name.clone(),
            template_id: self.template_id.clone(),
            owner: self.owner.clone(),
            local_workspace_path: self.local_workspace_path.clone(),
            bare_staging_path: self.bare_staging_path.clone(),
            github_synced: self.github_synced,
            github_url: self.github_url.clone(),
            private: self.private,
            vcs_mode: self.vcs_mode.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditLogEntry {
    pub id: u64,
    pub timestamp: String,
    pub repo_name: String,
    pub actor: String,
    pub action: String,
    pub allowed: bool,
    pub details: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct StateDbData {
    pub next_queue_id: u64,
    pub next_audit_id: u64,
    pub repos: HashMap<String, ManagedRepo>,
    pub queue: Vec<QueueItem>,
    pub audit_log: Vec<AuditLogEntry>,
}

pub struct StateStore {
    pub db_path: PathBuf,
    pub staging_dir: PathBuf,
    inner: Mutex<StateDbData>,
}

impl StateStore {
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_dir)?;
        set_dir_0700(&base_dir);
        let staging_dir = base_dir.join("staging");
        fs::create_dir_all(&staging_dir)?;
        set_dir_0700(&staging_dir);
        let db_path = base_dir.join("state_db.json");
        let data = if db_path.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600));
            }
            let raw = fs::read_to_string(&db_path).unwrap_or_default();
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            StateDbData {
                next_queue_id: 1,
                next_audit_id: 1,
                ..Default::default()
            }
        };
        Ok(Self {
            db_path,
            staging_dir,
            inner: Mutex::new(data),
        })
    }

    fn save_locked(&self, data: &StateDbData) -> Result<()> {
        let tmp = self.db_path.with_extension("json.tmp");
        let raw = serde_json::to_string_pretty(data)?;
        write_file_0600(&tmp, raw.as_bytes())?;
        fs::rename(&tmp, &self.db_path)?;
        Ok(())
    }

    pub fn snapshot(&self) -> StateDbData {
        self.inner.lock().unwrap().clone()
    }

    pub fn upsert_repo(&self, repo: ManagedRepo) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        guard.repos.insert(repo.name.clone(), repo);
        self.save_locked(&guard)
    }

    pub fn get_repo(&self, name: &str) -> Option<ManagedRepo> {
        let guard = self.inner.lock().unwrap();
        guard.repos.get(name).cloned()
    }

    pub fn mark_repo_synced(&self, name: &str, github_url: String) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(r) = guard.repos.get_mut(name) {
            r.github_synced = true;
            r.github_url = Some(github_url);
        }
        self.save_locked(&guard)
    }

    pub fn enqueue_item(
        &self,
        kind: QueueItemKind,
        repo_name: String,
        title: String,
        description: String,
        source_branch: String,
        target_branch: String,
        old_sha: String,
        new_sha: String,
        private_repo: bool,
        vcs_mode: String,
        diff_summary: String,
    ) -> Result<QueueItem> {
        let mut guard = self.inner.lock().unwrap();
        if guard.next_queue_id == 0 {
            guard.next_queue_id = 1;
        }
        let id = guard.next_queue_id;
        guard.next_queue_id += 1;

        let item = QueueItem {
            id,
            kind,
            status: QueueItemStatus::Pending,
            repo_name,
            title,
            description,
            source_branch,
            target_branch,
            old_sha,
            new_sha,
            private_repo,
            vcs_mode,
            diff_summary,
            created_at: Utc::now().to_rfc3339(),
            resolved_at: None,
            error_message: None,
        };
        guard.queue.push(item.clone());
        self.save_locked(&guard)?;
        Ok(item)
    }

    pub fn set_item_status(
        &self,
        id: u64,
        status: QueueItemStatus,
        err_msg: Option<String>,
    ) -> Result<Option<QueueItem>> {
        let mut guard = self.inner.lock().unwrap();
        let mut found = None;
        for item in guard.queue.iter_mut() {
            if item.id == id {
                item.status = status.clone();
                if matches!(
                    status,
                    QueueItemStatus::Executed | QueueItemStatus::Rejected | QueueItemStatus::Failed
                ) {
                    item.resolved_at = Some(Utc::now().to_rfc3339());
                }
                item.error_message = err_msg;
                found = Some(item.clone());
                break;
            }
        }
        self.save_locked(&guard)?;
        Ok(found)
    }

    pub fn add_audit(
        &self,
        repo_name: &str,
        actor: &str,
        action: &str,
        allowed: bool,
        details: &str,
    ) {
        let mut guard = self.inner.lock().unwrap();
        if guard.next_audit_id == 0 {
            guard.next_audit_id = 1;
        }
        let id = guard.next_audit_id;
        guard.next_audit_id += 1;
        guard.audit_log.insert(
            0,
            AuditLogEntry {
                id,
                timestamp: Utc::now().to_rfc3339(),
                repo_name: repo_name.to_string(),
                actor: actor.to_string(),
                action: action.to_string(),
                allowed,
                details: details.to_string(),
            },
        );
        if guard.audit_log.len() > 250 {
            guard.audit_log.truncate(250);
        }
        let _ = self.save_locked(&guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_store_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gitolorin_queue_test_{}_{}_{}",
            prefix,
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn test_public_managed_repo_redacts_proxy_token_and_permissions() {
        let base = temp_store_dir("perms");
        let store = StateStore::new(base.clone()).unwrap();

        let repo = ManagedRepo {
            name: "demo-repo".to_string(),
            display_name: "Demo Repo".to_string(),
            template_id: "empty".to_string(),
            owner: "octocat".to_string(),
            local_workspace_path: "/tmp/demo-repo".to_string(),
            bare_staging_path: "/tmp/demo-repo.git".to_string(),
            github_synced: false,
            github_url: None,
            private: true,
            vcs_mode: "jj".to_string(),
            project_proxy_token: "olo_secret_proxy_token_abcdef123456".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let public_json = serde_json::to_string(&repo.to_public()).unwrap();
        assert!(!public_json.contains("olo_secret_proxy_token_abcdef123456"));
        assert!(!public_json.contains("project_proxy_token"));
        assert!(public_json.contains("demo-repo"));

        store.upsert_repo(repo).unwrap();
        assert!(store.db_path.is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let base_mode = fs::metadata(&base).unwrap().permissions().mode() & 0o777;
            let staging_mode = fs::metadata(&store.staging_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let db_mode = fs::metadata(&store.db_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(base_mode, 0o700);
            assert_eq!(staging_mode, 0o700);
            assert_eq!(db_mode, 0o600);
        }

        let _ = fs::remove_dir_all(&base);
    }
}
