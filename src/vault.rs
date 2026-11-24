use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroize;

/// Wrapper for secret strings kept briefly in RAM and wiped on drop.
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Sensitive Admin Credentials held only briefly in RAM and zeroed on drop.
#[derive(Serialize, Deserialize)]
pub struct AdminSecret {
    pub github_username: String,
    pub admin_pat: String,
    pub worker_pat_or_app_token: String,
}

impl fmt::Debug for AdminSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminSecret")
            .field("github_username", &self.github_username)
            .field("admin_pat", &"[REDACTED]")
            .field("worker_pat_or_app_token", &"[REDACTED]")
            .finish()
    }
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
    /// Optional OS biometric/system-auth wrapped key (encrypted with a random key isolated via OS auth)
    pub os_bio_enabled: bool,
    pub bio_wrapped_pin_b64: Option<String>,
    pub bio_nonce_b64: Option<String>,
    /// Storage backend for bio key: "root_polkit" | "macos_keychain" | "windows_dpapi"
    #[serde(default)]
    pub bio_key_storage: Option<String>,
    /// Indicates whether a worker token is stored inside the encrypted vault
    #[serde(default)]
    pub has_worker_token: bool,
    /// Registered WebAuthn Passkey credential ID (for browser fingerprint unlock)
    pub webauthn_cred_id: Option<String>,
}

/// Non-sensitive worker config stored separately without plaintext secrets.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct WorkerConfig {
    pub github_username: String,
    /// Legacy plaintext worker_token field: deserialized only to detect/clean old installs, never serialized.
    #[serde(default, rename = "worker_token", skip_serializing)]
    pub legacy_worker_token: Option<String>,
    pub default_vcs: String, // "git", "jj", "worktree"
    pub protected_branches: Vec<String>,
}

pub fn set_dir_0700(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

pub fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)?;
        Ok(())
    }
}

pub fn secure_wipe_and_remove(path: &Path) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() {
        let _ = fs::remove_file(path);
        return;
    }
    if meta.file_type().is_file() {
        let len = meta.len() as usize;
        if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
            let zeros = [0u8; 4096];
            let mut remaining = len;
            while remaining > 0 {
                let chunk = remaining.min(zeros.len());
                if f.write_all(&zeros[..chunk]).is_err() {
                    break;
                }
                remaining -= chunk;
            }
            let _ = f.sync_all();
        }
        let _ = fs::remove_file(path);
    }
}

fn fnv1a_64_hex(input: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in input {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)
}

fn dir_hash(base_dir: &Path) -> String {
    let resolved = fs::canonicalize(base_dir).unwrap_or_else(|_| base_dir.to_path_buf());
    fnv1a_64_hex(resolved.to_string_lossy().as_bytes())
}

pub fn linux_root_bio_key_path(base_dir: &Path) -> Result<PathBuf> {
    let out = Command::new("id")
        .arg("-u")
        .output()
        .context("Obteniendo UID del usuario actual")?;
    if !out.status.success() {
        return Err(anyhow!("Error obteniendo UID del usuario actual"));
    }
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if uid.is_empty() || !uid.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("UID inválido obtenido de 'id -u'"));
    }
    let dhash = dir_hash(base_dir);
    Ok(PathBuf::from(format!(
        "/etc/gitolorin/bio_seal_{}_{}.key",
        uid, dhash
    )))
}

#[cfg(target_os = "linux")]
fn store_linux_root_bio_key(root_path: &Path, bio_key: &[u8; 32]) -> Result<()> {
    if !Path::new("/usr/bin/pkexec").is_file() {
        return Err(anyhow!(
            "En Linux el desbloqueo biométrico seguro requiere Polkit (/usr/bin/pkexec)."
        ));
    }
    let mut child = Command::new("/usr/bin/pkexec")
        .args([
            "/bin/sh",
            "-c",
            "umask 077 && install -d -m 0700 -o root -g root /etc/gitolorin && cat > \"$1\" && chmod 0600 \"$1\" && chown root:root \"$1\"",
            "_",
        ])
        .arg(root_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Error invocando Polkit (pkexec) para guardar llave biométrica aislada")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(bio_key)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "No se pudo guardar la llave biométrica aislada en {} (Polkit cancelado o rechazado).",
            root_path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn load_linux_root_bio_key(root_path: &Path) -> Result<[u8; 32]> {
    if !Path::new("/usr/bin/pkexec").is_file() {
        return Err(anyhow!(
            "No se encontró Polkit (/usr/bin/pkexec) para leer la llave biométrica."
        ));
    }
    let out = Command::new("/usr/bin/pkexec")
        .arg("/bin/cat")
        .arg(root_path)
        .output()
        .context("Error invocando Polkit (pkexec) para desbloquear llave biométrica")?;
    let mut stdout = out.stdout;
    if !out.status.success() {
        stdout.zeroize();
        return Err(anyhow!(
            "Autenticación del sistema (Huella/Polkit) cancelada o fallida."
        ));
    }
    if stdout.len() != 32 {
        stdout.zeroize();
        return Err(anyhow!(
            "La llave biométrica almacenada en {} tiene un tamaño inválido.",
            root_path.display()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&stdout);
    stdout.zeroize();
    Ok(key)
}

#[cfg(target_os = "macos")]
fn store_macos_keychain_bio_key(base_dir: &Path, bio_key: &[u8; 32]) -> Result<()> {
    let account = dir_hash(base_dir);
    let mut hex_key = hex::encode(bio_key);
    let mut cmd_str = format!(
        "add-generic-password -U -s gitolorin-bio-seal -a {} -w {}\n",
        account, hex_key
    );
    hex_key.zeroize();

    let mut child = Command::new("security")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("Error ejecutando 'security -i' para Keychain de macOS")?;
    if let Some(mut stdin) = child.stdin.take() {
        let wres = stdin.write_all(cmd_str.as_bytes());
        cmd_str.zeroize();
        wres?;
    } else {
        cmd_str.zeroize();
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "No se pudo guardar la llave biométrica en macOS Keychain."
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn load_macos_keychain_bio_key(base_dir: &Path) -> Result<[u8; 32]> {
    let account = dir_hash(base_dir);
    let out = Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            "gitolorin-bio-seal",
            "-a",
            &account,
            "-w",
        ])
        .output()
        .context("Error leyendo llave biométrica de macOS Keychain")?;
    let mut stdout = out.stdout;
    if !out.status.success() {
        stdout.zeroize();
        return Err(anyhow!(
            "No se encontró la llave biométrica en macOS Keychain."
        ));
    }
    let trimmed = String::from_utf8_lossy(&stdout).trim().to_string();
    stdout.zeroize();
    let mut decoded = hex::decode(trimmed)?;
    if decoded.len() != 32 {
        decoded.zeroize();
        return Err(anyhow!("Llave biométrica inválida en macOS Keychain."));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(key)
}

#[cfg(target_os = "windows")]
fn store_windows_dpapi_bio_key(base_dir: &Path, bio_key: &[u8; 32]) -> Result<()> {
    let mut hex_key = hex::encode(bio_key);
    let dpapi_path = base_dir.join("bio_seal.dpapi");
    let ps = "Add-Type -AssemblyName System.Security; \
              $in = [Console]::In.ReadToEnd().Trim(); \
              $bytes = [System.Text.Encoding]::UTF8.GetBytes($in); \
              $prot = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); \
              [Convert]::ToBase64String($prot)";
    let mut child = Command::new("powershell")
        .args(["-NoProfile", "-Command", ps])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Error invocando DPAPI via PowerShell")?;
    if let Some(mut stdin) = child.stdin.take() {
        let wres = stdin.write_all(hex_key.as_bytes());
        hex_key.zeroize();
        wres?;
    } else {
        hex_key.zeroize();
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!("No se pudo proteger la llave biométrica con Windows DPAPI."));
    }
    write_file_0600(&dpapi_path, out.stdout.as_slice())?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn load_windows_dpapi_bio_key(base_dir: &Path) -> Result<[u8; 32]> {
    let dpapi_path = base_dir.join("bio_seal.dpapi");
    let b64_bytes = fs::read(&dpapi_path)
        .with_context(|| "No se encontró archivo DPAPI de llave biométrica.")?;
    let ps = "Add-Type -AssemblyName System.Security; \
              $in = [Console]::In.ReadToEnd().Trim(); \
              $enc = [Convert]::FromBase64String($in); \
              $raw = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); \
              [System.Text.Encoding]::UTF8.GetString($raw)";
    let mut child = Command::new("powershell")
        .args(["-NoProfile", "-Command", ps])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Error invocando DPAPI Unprotect via PowerShell")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&b64_bytes)?;
    }
    let out = child.wait_with_output()?;
    let mut stdout = out.stdout;
    if !out.status.success() {
        stdout.zeroize();
        return Err(anyhow!("No se pudo desencriptar la llave DPAPI de Windows."));
    }
    let mut hex_str = String::from_utf8_lossy(&stdout).trim().to_string();
    stdout.zeroize();
    let mut decoded = hex::decode(&hex_str)?;
    hex_str.zeroize();
    if decoded.len() != 32 {
        decoded.zeroize();
        return Err(anyhow!("Llave biométrica DPAPI inválida."));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(key)
}

pub struct VaultManager {
    pub base_dir: PathBuf,
}

impl VaultManager {
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_dir)?;
        set_dir_0700(&base_dir);
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
            legacy_worker_token: None,
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
        write_file_0600(&p, json.as_bytes())
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
        let cipher_res = Aes256Gcm::new_from_slice(&key);
        key.zeroize();
        let cipher = cipher_res.map_err(|e| anyhow!("Cipher init error: {}", e))?;

        let mut plaintext = serde_json::to_vec(secret)?;
        let enc_res = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref());
        plaintext.zeroize();
        let ciphertext = enc_res.map_err(|_| anyhow!("Error encriptando la bóveda AES-256-GCM"))?;

        // If OS biometric unlock is enabled, wrap the PIN with an ephemeral 32-byte key stored in an OS-isolated backend.
        let (bio_wrapped_pin_b64, bio_nonce_b64, bio_key_storage) = if os_bio_enabled {
            let mut bio_key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bio_key);
            let mut b_nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut b_nonce);

            let b_cipher = match Aes256Gcm::new_from_slice(&bio_key) {
                Ok(c) => c,
                Err(e) => {
                    bio_key.zeroize();
                    return Err(anyhow!("Bio cipher error: {}", e));
                }
            };
            let wrapped = match b_cipher
                .encrypt(Nonce::from_slice(&b_nonce), pin_or_passphrase.as_bytes())
            {
                Ok(w) => w,
                Err(_) => {
                    bio_key.zeroize();
                    return Err(anyhow!("Error envolviendo llave biométrica"));
                }
            };

            let storage_res: Result<String> = {
                #[cfg(target_os = "linux")]
                {
                    match linux_root_bio_key_path(&self.base_dir)
                        .and_then(|root_path| store_linux_root_bio_key(&root_path, &bio_key))
                    {
                        Ok(()) => Ok("root_polkit".to_string()),
                        Err(e) => Err(e),
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    store_macos_keychain_bio_key(&self.base_dir, &bio_key)
                        .map(|_| "macos_keychain".to_string())
                }
                #[cfg(target_os = "windows")]
                {
                    store_windows_dpapi_bio_key(&self.base_dir, &bio_key)
                        .map(|_| "windows_dpapi".to_string())
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
                {
                    Err(anyhow!("Plataforma no soportada para almacenamiento biométrico aislado."))
                }
            };
            bio_key.zeroize();
            let storage = storage_res?;
            (
                Some(B64.encode(wrapped)),
                Some(B64.encode(b_nonce)),
                Some(storage),
            )
        } else {
            (None, None, None)
        };

        // Always wipe and delete any legacy insecure `.bio_seal.key` on disk.
        secure_wipe_and_remove(&self.base_dir.join(".bio_seal.key"));

        let has_worker_token = !secret.worker_pat_or_app_token.trim().is_empty();
        let vault_file = EncryptedVaultFile {
            version: 1,
            github_username: secret.github_username.clone(),
            salt_b64: B64.encode(salt),
            nonce_b64: B64.encode(nonce_bytes),
            ciphertext_b64: B64.encode(ciphertext),
            os_bio_enabled,
            bio_wrapped_pin_b64,
            bio_nonce_b64,
            bio_key_storage,
            has_worker_token,
            webauthn_cred_id,
        };

        let serialized = serde_json::to_string_pretty(&vault_file)?;
        let vp = self.vault_path();
        write_file_0600(&vp, serialized.as_bytes())?;

        // Update non-sensitive worker config (never writing plaintext worker_token to disk)
        let mut wcfg = self.load_worker_config();
        wcfg.github_username = secret.github_username.clone();
        wcfg.legacy_worker_token = None;
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
        let cipher_res = Aes256Gcm::new_from_slice(&key);
        key.zeroize();
        let cipher = cipher_res.map_err(|e| anyhow!("Cipher init error: {}", e))?;

        let mut plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| anyhow!("PIN / Clave de bóveda incorrecta. ¡You Shall Not Pass!"))?;

        let secret_res = serde_json::from_slice::<AdminSecret>(&plaintext);
        plaintext.zeroize();
        let secret = secret_res?;
        Ok(secret)
    }

    /// Trigger OS-native Biometric / System Authentication prompt (Linux Polkit/fprintd, macOS TouchID, Windows Hello)
    /// and unseal the vault in RAM for the batch approval operation.
    pub fn unseal_with_os_biometrics(&self, reason: &str) -> Result<AdminSecret> {
        let vp = self.vault_path();
        let raw = fs::read_to_string(&vp)
            .with_context(|| "La bóveda Admin no está inicializada.")?;
        let mut vf: EncryptedVaultFile = serde_json::from_str(&raw)?;

        if !vf.os_bio_enabled {
            return Err(anyhow!(
                "El desbloqueo por huella del sistema no está habilitado en esta bóveda. Usa tu PIN."
            ));
        }

        let wrapped_b64 = vf
            .bio_wrapped_pin_b64
            .as_ref()
            .ok_or_else(|| anyhow!("No hay llave biométrica registrada en la bóveda."))?;
        let nonce_b64 = vf
            .bio_nonce_b64
            .as_ref()
            .ok_or_else(|| anyhow!("Falta nonce biométrico."))?;

        let mut bio_key: [u8; 32] = match vf.bio_key_storage.as_deref() {
            Some("root_polkit") => {
                #[cfg(target_os = "linux")]
                {
                    let _ = reason;
                    let root_path = linux_root_bio_key_path(&self.base_dir)?;
                    load_linux_root_bio_key(&root_path)?
                }
                #[cfg(not(target_os = "linux"))]
                {
                    return Err(anyhow!("El almacenamiento 'root_polkit' solo es compatible en Linux."));
                }
            }
            Some("macos_keychain") => {
                #[cfg(target_os = "macos")]
                {
                    Self::prompt_os_biometric_consent(reason)?;
                    load_macos_keychain_bio_key(&self.base_dir)?
                }
                #[cfg(not(target_os = "macos"))]
                {
                    return Err(anyhow!("El almacenamiento 'macos_keychain' solo es compatible en macOS."));
                }
            }
            Some("windows_dpapi") => {
                #[cfg(target_os = "windows")]
                {
                    Self::prompt_os_biometric_consent(reason)?;
                    load_windows_dpapi_bio_key(&self.base_dir)?
                }
                #[cfg(not(target_os = "windows"))]
                {
                    return Err(anyhow!("El almacenamiento 'windows_dpapi' solo es compatible en Windows."));
                }
            }
            None => {
                #[cfg(target_os = "linux")]
                {
                    let _ = reason;
                    let legacy_path = self.base_dir.join(".bio_seal.key");
                    if legacy_path.is_file() && Path::new("/usr/bin/pkexec").is_file() {
                        let mut legacy_bytes = fs::read(&legacy_path)?;
                        if legacy_bytes.len() != 32 {
                            legacy_bytes.zeroize();
                            return Err(anyhow!("Llave biométrica heredada inválida."));
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&legacy_bytes);
                        legacy_bytes.zeroize();

                        let root_path = match linux_root_bio_key_path(&self.base_dir) {
                            Ok(p) => p,
                            Err(e) => {
                                arr.zeroize();
                                return Err(e);
                            }
                        };
                        if let Err(e) = store_linux_root_bio_key(&root_path, &arr) {
                            arr.zeroize();
                            return Err(e);
                        }
                        vf.bio_key_storage = Some("root_polkit".to_string());
                        if let Ok(updated) = serde_json::to_string_pretty(&vf) {
                            let _ = write_file_0600(&vp, updated.as_bytes());
                        }
                        secure_wipe_and_remove(&legacy_path);
                        arr
                    } else {
                        return Err(anyhow!(
                            "Esta bóveda usa un formato biométrico heredado sin aislamiento. Desbloquea con tu PIN y vuelve a sellar la bóveda."
                        ));
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = reason;
                    return Err(anyhow!(
                        "Esta bóveda usa un formato biométrico heredado sin aislamiento. Desbloquea con tu PIN y vuelve a sellar la bóveda."
                    ));
                }
            }
            Some(other) => {
                return Err(anyhow!(
                    "Método de almacenamiento biométrico desconocido: {}",
                    other
                ));
            }
        };

        let cipher_res = Aes256Gcm::new_from_slice(&bio_key);
        bio_key.zeroize();
        let cipher =
            cipher_res.map_err(|e| anyhow!("Error inicializando cifrado biométrico: {}", e))?;
        let wrapped = B64.decode(wrapped_b64)?;
        let nonce = B64.decode(nonce_b64)?;

        let pin_bytes = cipher
            .decrypt(Nonce::from_slice(&nonce), wrapped.as_ref())
            .map_err(|_| anyhow!("No se pudo desencriptar la llave biométrica local."))?;
        let mut pin_str = match String::from_utf8(pin_bytes) {
            Ok(s) => s,
            Err(e) => {
                let mut raw_b = e.into_bytes();
                raw_b.zeroize();
                return Err(anyhow!("PIN biométrico inválido (UTF-8)."));
            }
        };

        let res = self.unseal_with_pin(&pin_str);
        pin_str.zeroize();
        res
    }

    /// Cross-platform OS Biometric / System Auth verification:
    /// - Linux: `pkexec /bin/true` (Polkit PAM prompt with fingerprint/password) or `fprintd-verify`
    /// - macOS: Touch ID / LocalAuthentication via osascript prompt
    /// - Windows: Windows Hello `UserConsentVerifier` via PowerShell WinRT bridge
    pub fn prompt_os_biometric_consent(reason: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let _ = reason;
            let has_gui =
                std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();

            if has_gui && Path::new("/usr/bin/pkexec").is_file() {
                let status = Command::new("/usr/bin/pkexec")
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
                let status = Command::new("/usr/bin/pkexec")
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
        let legacy_insecure_bio_key = self.base_dir.join(".bio_seal.key").is_file();
        let legacy_plaintext_worker_token = wcfg
            .legacy_worker_token
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if !vp.is_file() {
            return serde_json::json!({
                "initialized": false,
                "github_username": wcfg.github_username,
                "has_worker_token": legacy_plaintext_worker_token,
                "os_bio_enabled": false,
                "bio_key_storage": null,
                "legacy_insecure_bio_key": legacy_insecure_bio_key,
                "legacy_plaintext_worker_token": legacy_plaintext_worker_token,
                "webauthn_registered": false,
                "default_vcs": wcfg.default_vcs,
                "protected_branches": wcfg.protected_branches,
            });
        }
        let vf: Option<EncryptedVaultFile> = fs::read_to_string(&vp)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        let has_worker_token = vf.as_ref().map(|v| v.has_worker_token).unwrap_or(false)
            || legacy_plaintext_worker_token;
        serde_json::json!({
            "initialized": true,
            "github_username": vf.as_ref().map(|v| v.github_username.clone()).unwrap_or(wcfg.github_username),
            "has_worker_token": has_worker_token,
            "os_bio_enabled": vf.as_ref().map(|v| v.os_bio_enabled).unwrap_or(false),
            "bio_key_storage": vf.as_ref().and_then(|v| v.bio_key_storage.clone()),
            "legacy_insecure_bio_key": legacy_insecure_bio_key,
            "legacy_plaintext_worker_token": legacy_plaintext_worker_token,
            "webauthn_registered": vf.as_ref().and_then(|v| v.webauthn_cred_id.clone()).is_some(),
            "webauthn_cred_id": vf.as_ref().and_then(|v| v.webauthn_cred_id.clone()),
            "default_vcs": wcfg.default_vcs,
            "protected_branches": wcfg.protected_branches,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_vault_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gitolorin_vault_test_{}_{}_{}",
            prefix,
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn test_seal_unseal_and_no_plaintext_secrets_on_disk() {
        let base = temp_vault_dir("roundtrip");
        let vm = VaultManager::new(base.clone()).unwrap();

        // Simulate legacy plaintext worker_token & insecure .bio_seal.key on disk
        let legacy_cfg = serde_json::json!({
            "github_username": "octocat",
            "worker_token": "ghp_legacy_plaintext_worker_secret_123456",
            "default_vcs": "jj",
            "protected_branches": ["main"]
        });
        fs::write(
            vm.worker_config_path(),
            serde_json::to_string_pretty(&legacy_cfg).unwrap(),
        )
        .unwrap();
        let legacy_bio = base.join(".bio_seal.key");
        fs::write(&legacy_bio, [42u8; 32]).unwrap();
        assert!(vm.get_public_status()["legacy_insecure_bio_key"]
            .as_bool()
            .unwrap());
        assert!(vm.get_public_status()["legacy_plaintext_worker_token"]
            .as_bool()
            .unwrap());

        let secret = AdminSecret {
            github_username: "octocat".to_string(),
            admin_pat: "ghp_super_secret_admin_pat_987654321".to_string(),
            worker_pat_or_app_token: "ghp_super_secret_worker_pat_123456789".to_string(),
        };

        // Debug representation must redact secrets
        let dbg = format!("{:?}", secret);
        assert!(!dbg.contains("ghp_super_secret_admin_pat"));
        assert!(!dbg.contains("ghp_super_secret_worker_pat"));
        let ss = SecretString::new("ghp_secret_string_value".to_string());
        assert!(!format!("{:?}", ss).contains("ghp_secret_string_value"));

        vm.seal_vault(&secret, "my-strong-pin", false, None)
            .unwrap();

        // Legacy insecure files must be gone and plaintext worker_token must be absent
        assert!(!legacy_bio.exists());
        let wcfg_raw = fs::read_to_string(vm.worker_config_path()).unwrap();
        assert!(!wcfg_raw.contains("ghp_super_secret_worker_pat"));
        assert!(!wcfg_raw.contains("ghp_legacy_plaintext_worker_secret"));
        assert!(!wcfg_raw.contains("\"worker_token\""));

        let vault_raw = fs::read_to_string(vm.vault_path()).unwrap();
        assert!(!vault_raw.contains("ghp_super_secret_admin_pat"));
        assert!(!vault_raw.contains("ghp_super_secret_worker_pat"));

        let status = vm.get_public_status();
        assert!(status["initialized"].as_bool().unwrap());
        assert!(status["has_worker_token"].as_bool().unwrap());
        assert!(!status["legacy_insecure_bio_key"].as_bool().unwrap());
        assert!(!status["legacy_plaintext_worker_token"].as_bool().unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(&base).unwrap().permissions().mode() & 0o777;
            let vault_mode = fs::metadata(vm.vault_path()).unwrap().permissions().mode() & 0o777;
            let wcfg_mode = fs::metadata(vm.worker_config_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(vault_mode, 0o600);
            assert_eq!(wcfg_mode, 0o600);
        }

        // Wrong PIN fails
        assert!(vm.unseal_with_pin("wrong-pin").is_err());

        // Right PIN succeeds and restores worker token from encrypted vault
        let unsealed = vm.unseal_with_pin("my-strong-pin").unwrap();
        assert_eq!(unsealed.github_username, "octocat");
        assert_eq!(unsealed.admin_pat, "ghp_super_secret_admin_pat_987654321");
        assert_eq!(
            unsealed.worker_pat_or_app_token,
            "ghp_super_secret_worker_pat_123456789"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_linux_root_bio_key_path_format() {
        let base = temp_vault_dir("biopath");
        fs::create_dir_all(&base).unwrap();
        let p = linux_root_bio_key_path(&base).unwrap();
        let s = p.to_string_lossy();
        assert!(s.starts_with("/etc/gitolorin/bio_seal_"));
        assert!(s.ends_with(".key"));
        assert_eq!(linux_root_bio_key_path(&base).unwrap(), p);
        let _ = fs::remove_dir_all(&base);
    }
}
