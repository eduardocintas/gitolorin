use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::Zeroize;

/// Sensitive Admin Credentials held only briefly in RAM and zeroed on drop.
#[derive(Serialize, Deserialize, Clone)]
pub struct AdminSecret {
    pub github_username: String,
    pub admin_pat: String,
    pub worker_pat_or_app_token: String,
}

impl Drop for AdminSecret {
    fn drop(&mut self) {
        self.github_username.zeroize();
        self.admin_pat.zeroize();
        self.worker_pat_or_app_token.zeroize();
    }
}

/// On-disk encrypted vault file (`~/.gitolorin/admin.vault`)
#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedVaultFile {
    pub version: u8,
    pub github_username: String,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    /// Optional OS biometric/system-auth wrapped key (encrypted with a random key stored in OS keyring or unlocked via OS auth)
    pub os_bio_enabled: bool,
    pub bio_wrapped_pin_b64: Option<String>,
    pub bio_nonce_b64: Option<String>,
    /// Registered WebAuthn Passkey credential ID (for browser fingerprint unlock)
    pub webauthn_cred_id: Option<String>,
}

/// Non-sensitive worker config stored separately for low-privilege operations (feature branch pushes)
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct WorkerConfig {
    pub github_username: String,
    /// Low-privilege token or GitHub App installation token restricted by the local proxy
    /// (The proxy strictly blocks using this token on main/master, force-push, or repo deletion)
    pub worker_token: Option<String>,
    pub default_vcs: String, // "git", "jj", "worktree"
    pub protected_branches: Vec<String>,
}

pub struct VaultManager {
    pub base_dir: PathBuf,
}

impl VaultManager {
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    pub fn vault_path(&self) -> PathBuf {
        self.base_dir.join("admin.vault")
    }

    pub fn worker_config_path(&self) -> PathBuf {
        self.base_dir.join("worker_config.json")
    }

    pub fn is_initialized(&self) -> bool {
        self.vault_path().is_file()
    }

    pub fn load_worker_config(&self) -> WorkerConfig {
        let p = self.worker_config_path();
        if let Ok(raw) = fs::read_to_string(&p) {
            if let Ok(cfg) = serde_json::from_str::<WorkerConfig>(&raw) {
                return cfg;
            }
        }
        WorkerConfig {
            github_username: String::new(),
            worker_token: None,
            default_vcs: "jj".to_string(),
            protected_branches: vec![
                "main".to_string(),
                "master".to_string(),
                "production".to_string(),
                "release".to_string(),
            ],
        }
    }

    pub fn save_worker_config(&self, cfg: &WorkerConfig) -> Result<()> {
        let p = self.worker_config_path();
        let json = serde_json::to_string_pretty(cfg)?;
        fs::write(&p, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn derive_key(pin_or_passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(pin_or_passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow!("Argon2 key derivation error: {}", e))?;
        Ok(key)
    }

    /// Initialize or update the encrypted Admin Vault with AES-256-GCM + Argon2id
    pub fn seal_vault(
        &self,
        secret: &AdminSecret,
        pin_or_passphrase: &str,
        os_bio_enabled: bool,
        webauthn_cred_id: Option<String>,
    ) -> Result<()> {
        if pin_or_passphrase.trim().len() < 4 {
            return Err(anyhow!(
                "El PIN o clave de la bóveda debe tener al menos 4 caracteres."
            ));
        }

        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let mut key = Self::derive_key(pin_or_passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow!("Cipher init error: {}", e))?;
        key.zeroize();

        let plaintext = serde_json::to_vec(secret)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|_| anyhow!("Error encriptando la bóveda AES-256-GCM"))?;

        // If OS biometric unlock is enabled, wrap the PIN with a machine-bound key that requires OS native biometric/polkit auth
        let (bio_wrapped_pin_b64, bio_nonce_b64) = if os_bio_enabled {
            let bio_key = self.get_or_create_machine_bio_key()?;
            let mut b_nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut b_nonce);
            let b_cipher = Aes256Gcm::new_from_slice(&bio_key)
                .map_err(|e| anyhow!("Bio cipher error: {}", e))?;
            let wrapped = b_cipher
                .encrypt(Nonce::from_slice(&b_nonce), pin_or_passphrase.as_bytes())
                .map_err(|_| anyhow!("Error envolviendo llave biométrica"))?;
            (Some(B64.encode(wrapped)), Some(B64.encode(b_nonce)))
        } else {
            (None, None)
        };

        let vault_file = EncryptedVaultFile {
            version: 1,
            github_username: secret.github_username.clone(),
            salt_b64: B64.encode(salt),
            nonce_b64: B64.encode(nonce_bytes),
            ciphertext_b64: B64.encode(ciphertext),
            os_bio_enabled,
            bio_wrapped_pin_b64,
            bio_nonce_b64,
            webauthn_cred_id,
        };

        let serialized = serde_json::to_string_pretty(&vault_file)?;
        let vp = self.vault_path();
        fs::write(&vp, serialized)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&vp, fs::Permissions::from_mode(0o600));
        }

        // Also update worker config with low-privilege worker token
        let mut wcfg = self.load_worker_config();
        wcfg.github_username = secret.github_username.clone();
        if !secret.worker_pat_or_app_token.trim().is_empty() {
            wcfg.worker_token = Some(secret.worker_pat_or_app_token.clone());
        }
        self.save_worker_config(&wcfg)?;

        Ok(())
    }

    /// Decrypt the Admin Vault in RAM using the user's PIN/Passphrase.
    /// The returned `AdminSecret` implements `ZeroizeOnDrop`, wiping memory immediately after use.
    pub fn unseal_with_pin(&self, pin_or_passphrase: &str) -> Result<AdminSecret> {
        let vp = self.vault_path();
        let raw = fs::read_to_string(&vp)
            .with_context(|| "La bóveda Admin aún no está configurada (ejecuta setup en la UI o CLI)")?;
        let vf: EncryptedVaultFile = serde_json::from_str(&raw)?;

        let salt = B64.decode(&vf.salt_b64)?;
        let nonce_bytes = B64.decode(&vf.nonce_b64)?;
        let ciphertext = B64.decode(&vf.ciphertext_b64)?;

        let mut key = Self::derive_key(pin_or_passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow!("Cipher init error: {}", e))?;
        key.zeroize();

        let mut plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| anyhow!("PIN / Clave de bóveda incorrecta. ¡You Shall Not Pass!"))?;

        let secret: AdminSecret = serde_json::from_slice(&plaintext)?;
        plaintext.zeroize();
        Ok(secret)
    }

    /// Trigger OS-native Biometric / System Authentication prompt (Linux Polkit/fprintd, macOS TouchID, Windows Hello)
    /// and unseal the vault in RAM for the batch approval operation.
    pub fn unseal_with_os_biometrics(&self, reason: &str) -> Result<AdminSecret> {
        let vp = self.vault_path();
        let raw = fs::read_to_string(&vp)
            .with_context(|| "La bóveda Admin no está inicializada.")?;
        let vf: EncryptedVaultFile = serde_json::from_str(&raw)?;

        if !vf.os_bio_enabled {
            return Err(anyhow!(
                "El desbloqueo por huella del sistema no está habilitado en esta bóveda. Usa tu PIN."
            ));
        }

        // Verify OS biometric consent first
        Self::prompt_os_biometric_consent(reason)?;

        let wrapped_b64 = vf
            .bio_wrapped_pin_b64
            .as_ref()
            .ok_or_else(|| anyhow!("No hay llave biométrica registrada en la bóveda."))?;
        let nonce_b64 = vf
            .bio_nonce_b64
            .as_ref()
            .ok_or_else(|| anyhow!("Falta nonce biométrico."))?;

        let bio_key = self.get_or_create_machine_bio_key()?;
        let cipher = Aes256Gcm::new_from_slice(&bio_key)
            .map_err(|e| anyhow!("Error inicializando cifrado biométrico: {}", e))?;
        let wrapped = B64.decode(wrapped_b64)?;
        let nonce = B64.decode(nonce_b64)?;

        let mut pin_bytes = cipher
            .decrypt(Nonce::from_slice(&nonce), wrapped.as_ref())
            .map_err(|_| anyhow!("No se pudo desencriptar la llave biométrica local."))?;
        let pin_str = String::from_utf8(pin_bytes.clone())?;
        pin_bytes.zeroize();

        let res = self.unseal_with_pin(&pin_str);
        Ok(res?)
    }

    fn get_or_create_machine_bio_key(&self) -> Result<[u8; 32]> {
        let key_path = self.base_dir.join(".bio_seal.key");
        if key_path.is_file() {
            let bytes = fs::read(&key_path)?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(arr);
            }
        }
        let mut arr = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut arr);
        fs::write(&key_path, &arr)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }
        Ok(arr)
    }

    /// Cross-platform OS Biometric / System Auth verification:
    /// - Linux: `fprintd-verify` (direct fingerprint reader) or `pkexec true` (Polkit PAM prompt with fingerprint/password)
    /// - macOS: Touch ID / LocalAuthentication via swift/osascript prompt
    /// - Windows: Windows Hello `UserConsentVerifier` via PowerShell WinRT bridge
    pub fn prompt_os_biometric_consent(_reason: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let has_gui =
                std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();

            // In a graphical session, invoke Polkit immediately (0ms delay) so it shows the
            // native fingerprint/password dialog directly without waiting on headless fprintd-verify.
            if has_gui && Path::new("/usr/bin/pkexec").is_file() {
                let status = Command::new("pkexec")
                    .arg("/usr/bin/true")
                    .status()
                    .context("Error invocando Polkit (pkexec) para autenticación del sistema")?;
                if status.success() {
                    return Ok(());
                }
                return Err(anyhow!(
                    "Autenticación del sistema (Huella/Polkit) cancelada o fallida."
                ));
            }

            // Headless / TTY fallback: use fprintd-verify directly if enrolled
            if Path::new("/usr/bin/fprintd-verify").is_file() {
                if let Ok(out) = Command::new("fprintd-list")
                    .arg(std::env::var("USER").unwrap_or_else(|_| "root".to_string()))
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    if stdout.contains("- #") {
                        let status = Command::new("fprintd-verify").status()?;
                        if status.success() {
                            return Ok(());
                        }
                    }
                }
            }

            if Path::new("/usr/bin/pkexec").is_file() {
                let status = Command::new("pkexec")
                    .arg("/usr/bin/true")
                    .status()
                    .context("Error invocando Polkit (pkexec) para autenticación del sistema")?;
                if status.success() {
                    return Ok(());
                }
                return Err(anyhow!(
                    "Autenticación del sistema (Huella/Polkit) cancelada o fallida."
                ));
            }
            return Err(anyhow!(
                "No se encontró lector de huellas (fprintd) ni Polkit (pkexec) activo."
            ));
        }

        #[cfg(target_os = "macos")]
        {
            let script = format!(
                "do shell script \"/usr/bin/true\" with prompt \"{}\" with administrator privileges",
                reason.replace('"', "'")
            );
            let status = Command::new("osascript").arg("-e").arg(script).status()?;
            if status.success() {
                return Ok(());
            }
            return Err(anyhow!("Autenticación Touch ID / macOS cancelada."));
        }

        #[cfg(target_os = "windows")]
        {
            let ps_script = format!(
                "$null = [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]; \
                 $op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('{}'); \
                 while ($op.Status -eq 0) {{ Start-Sleep -Milliseconds 100 }}; \
                 if ($op.GetResults() -eq 'Verified') {{ exit 0 }} else {{ exit 1 }}",
                reason.replace('\'', "")
            );
            let status = Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps_script])
                .status()?;
            if status.success() {
                return Ok(());
            }
            return Err(anyhow!("Autenticación Windows Hello cancelada o fallida."));
        }

        #[allow(unreachable_code)]
        Err(anyhow!("Plataforma no soportada para biometría nativa."))
    }

    pub fn get_public_status(&self) -> serde_json::Value {
        let vp = self.vault_path();
        let wcfg = self.load_worker_config();
        if !vp.is_file() {
            return serde_json::json!({
                "initialized": false,
                "github_username": wcfg.github_username,
                "has_worker_token": wcfg.worker_token.is_some(),
                "os_bio_enabled": false,
                "webauthn_registered": false,
                "default_vcs": wcfg.default_vcs,
                "protected_branches": wcfg.protected_branches,
            });
        }
        let vf: Option<EncryptedVaultFile> = fs::read_to_string(&vp)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        serde_json::json!({
            "initialized": true,
            "github_username": vf.as_ref().map(|v| v.github_username.clone()).unwrap_or(wcfg.github_username),
            "has_worker_token": wcfg.worker_token.is_some(),
            "os_bio_enabled": vf.as_ref().map(|v| v.os_bio_enabled).unwrap_or(false),
            "webauthn_registered": vf.as_ref().and_then(|v| v.webauthn_cred_id.clone()).is_some(),
            "webauthn_cred_id": vf.as_ref().and_then(|v| v.webauthn_cred_id.clone()),
            "default_vcs": wcfg.default_vcs,
            "protected_branches": wcfg.protected_branches,
        })
    }
}
