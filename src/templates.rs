use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

const RUST_WEB_APP_BUILTIN_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMeta {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub builtin: bool,
    #[serde(default)]
    pub builtin_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub builtin: bool,
    pub file_count: usize,
    pub files: HashMap<String, String>,
}

pub fn templates_root(base_dir: &Path) -> PathBuf {
    base_dir.join("templates")
}

fn validate_template_id(id: &str) -> Result<String> {
    let clean = id.trim().to_string();
    if clean.is_empty()
        || !clean
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "ID de template inválido '{}'. Usa solo letras, números, guiones o guiones bajos.",
            clean
        ));
    }
    Ok(clean)
}

fn validate_rel_path(rel: &str) -> Result<PathBuf> {
    let p = Path::new(rel.trim());
    if p.is_absolute() {
        return Err(anyhow!("Ruta relativa inválida: {}", rel));
    }
    for c in p.components() {
        if matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)) {
            return Err(anyhow!("Ruta inválida (path traversal no permitido): {}", rel));
        }
    }
    Ok(p.to_path_buf())
}

pub fn ensure_builtin_templates(base_dir: &Path) -> Result<()> {
    let root = templates_root(base_dir);
    fs::create_dir_all(&root)?;

    // 1. `empty` template
    let empty_dir = root.join("empty");
    if !empty_dir.join("template.json").is_file() {
        fs::create_dir_all(empty_dir.join("files"))?;
        let meta = TemplateMeta {
            id: "empty".to_string(),
            name: "Vacío (Solo Git/jj + AGENTS.md)".to_string(),
            description: "Inicializa el repositorio protegido sin archivos de código extra.".to_string(),
            builtin: true,
            builtin_version: 1,
        };
        fs::write(
            empty_dir.join("template.json"),
            serde_json::to_string_pretty(&meta)?,
        )?;
    }

    // 2. `rust-web-app` template (Portable Rust Axum + embedded Web UI + `app` mode)
    let rust_dir = root.join("rust-web-app");
    let rust_meta_path = rust_dir.join("template.json");
    let should_write_rust = if !rust_meta_path.is_file() {
        true
    } else if let Ok(raw) = fs::read_to_string(&rust_meta_path) {
        if let Ok(existing_meta) = serde_json::from_str::<TemplateMeta>(&raw) {
            existing_meta.builtin && existing_meta.builtin_version < RUST_WEB_APP_BUILTIN_VERSION
        } else {
            false
        }
    } else {
        false
    };

    if should_write_rust {
        let mut files = HashMap::new();
        files.insert(
            ".gitignore".to_string(),
            "/target\n.DS_Store\n.env\n".to_string(),
        );
        files.insert(
            "Cargo.toml".to_string(),
            r#"[package]
name = "{{REPO_NAME}}"
version = "0.1.0"
edition = "2021"
rust-version = "1.80"
description = "{{DISPLAY_NAME}}"
license = "{{LICENSE}}"

[dependencies]
axum = "0.8"
tokio = { version = "1.44", features = ["rt-multi-thread", "macros", "net"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
rand = "0.8"
hex = "0.4"
"#
            .to_string(),
        );
        files.insert(
            "README.md".to_string(),
            r#"# {{DISPLAY_NAME}} (`{{REPO_NAME}}`)

Portable Rust + Web UI application.

## Quick Start

```bash
cargo run -- app
```
"#
            .to_string(),
        );
        files.insert(
            "static/index.html".to_string(),
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{{DISPLAY_NAME}}</title>
  <style>
    body { margin: 0; font-family: system-ui, sans-serif; background: #0d1117; color: #e6edf3; display: grid; place-items: center; min-height: 100vh; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 28px 36px; max-width: 520px; }
    h1 { margin: 0 0 8px; font-size: 1.4rem; }
    p { margin: 0 0 14px; color: #8b949e; }
    button { background: #238636; color: #fff; border: 0; border-radius: 8px; padding: 8px 14px; cursor: pointer; font-weight: 600; }
    pre { margin: 12px 0 0; padding: 10px; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>{{DISPLAY_NAME}}</h1>
    <p>Portable Rust (Axum) + Embedded Web UI (<code>{{REPO_NAME}}</code>).</p>
    <button id="btn-ping">Test Authenticated POST /api/ping</button>
    <pre id="out">Checking /api/health...</pre>
  </div>
  <script>
    const out = document.getElementById("out");
    fetch("/api/health", { credentials: "same-origin" })
      .then((r) => r.json())
      .then((d) => { out.textContent = JSON.stringify(d, null, 2); })
      .catch((e) => { out.textContent = "Error: " + e; });

    document.getElementById("btn-ping").addEventListener("click", async () => {
      const res = await fetch("/api/ping", { method: "POST", credentials: "same-origin" });
      out.textContent = JSON.stringify(await res.json(), null, 2);
    });
  </script>
</body>
</html>
"#
            .to_string(),
        );
        files.insert(
            "src/main.rs".to_string(),
            r#"use axum::{
    extract::{Request, State},
    http::{header, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::path::PathBuf;
use std::sync::Arc;

const INDEX_HTML: &str = include_str!("../static/index.html");
const SESSION_COOKIE_NAME: &str = "{{REPO_NAME}}_session";

#[derive(Clone)]
struct AppState {
    port: u16,
    session_token: String,
}

#[derive(Parser)]
#[command(name = "{{REPO_NAME}}", about = "{{DISPLAY_NAME}}")]
struct Cli {
    #[arg(long, global = true, default_value_t = 9450)]
    port: u16,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Serve,
    App,
}

fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn is_allowed_host(host: &str, port: u16) -> bool {
    let h = host.trim();
    h == format!("{{REPO_NAME}}.localhost:{}", port)
        || h == format!("localhost:{}", port)
        || h == format!("127.0.0.1:{}", port)
        || h == format!("[::1]:{}", port)
}

fn is_allowed_origin(origin: &str, port: u16) -> bool {
    let o = origin.trim();
    o == format!("http://{{REPO_NAME}}.localhost:{}", port)
        || o == format!("http://localhost:{}", port)
        || o == format!("http://127.0.0.1:{}", port)
        || o == format!("http://[::1]:{}", port)
}

fn has_valid_session_cookie(headers: &header::HeaderMap, expected: &str) -> bool {
    let Some(raw) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let prefix = format!("{}=", SESSION_COOKIE_NAME);
    raw.split(';')
        .map(str::trim)
        .any(|part| part.strip_prefix(&prefix).is_some_and(|val| val == expected))
}

async fn csrf_guard(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let is_mutating = matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    );
    if is_mutating && req.uri().path().starts_with("/api/") {
        let host_ok = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|h| is_allowed_host(h, state.port));
        let origin_ok = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|o| is_allowed_origin(o, state.port))
            .unwrap_or(true);
        let cookie_ok = has_valid_session_cookie(req.headers(), &state.session_token);

        if !(host_ok && origin_ok && cookie_ok) {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": "forbidden" })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

async fn serve_index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cookie = format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/",
        SESSION_COOKIE_NAME, state.session_token
    );
    (
        [
            (header::SET_COOKIE, cookie),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Html(INDEX_HTML),
    )
}

async fn api_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "app": "{{REPO_NAME}}" }))
}

async fn api_ping() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "pong": true }))
}

fn launch_app_window(url: &str) {
    // Linux desktop entry: StartupWMClass=chrome-{{REPO_NAME}}.localhost__-Default
    let profile_dir = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|h| h.join(".local/share/{{REPO_NAME}}/webapp-profile"))
        .unwrap_or_else(|| PathBuf::from("/tmp/{{REPO_NAME}}-webapp-profile"));
    let _ = std::fs::create_dir_all(&profile_dir);

    let app_arg = format!("--app={}", url);
    let profile_arg = format!("--user-data-dir={}", profile_dir.display());
    for bin in [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "brave-browser",
        "microsoft-edge",
    ] {
        if std::process::Command::new(bin)
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
            .is_ok()
        {
            return;
        }
    }
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let url = format!("http://{{REPO_NAME}}.localhost:{}", cli.port);
    let state = Arc::new(AppState {
        port: cli.port,
        session_token: generate_session_token(),
    });

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/health", get(api_health))
        .route("/api/ping", post(api_ping))
        .layer(middleware::from_fn_with_state(state.clone(), csrf_guard))
        .with_state(state);

    let v4 = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", cli.port))
        .await
        .expect("bind 127.0.0.1");
    if let Ok(v6) = tokio::net::TcpListener::bind(format!("[::1]:{}", cli.port)).await {
        let app_v6 = app.clone();
        tokio::spawn(async move {
            let _ = axum::serve(v6, app_v6).await;
        });
    }

    if matches!(cli.command, Some(Commands::App)) {
        launch_app_window(&url);
    }

    println!("{{DISPLAY_NAME}} listening on {}", url);
    axum::serve(v4, app).await.expect("serve");
}
"#
            .to_string(),
        );

        save_template_internal(
            base_dir,
            "rust-web-app",
            "Rust + Web UI Portable (Axum + static/)",
            "Starter portable en 1 binario Rust (Axum 0.8 + Clap + Cookie CSRF + *.localhost + modo App).",
            true,
            files,
        )?;
    }

    Ok(())
}

fn save_template_internal(
    base_dir: &Path,
    id: &str,
    name: &str,
    description: &str,
    builtin: bool,
    files: HashMap<String, String>,
) -> Result<TemplateInfo> {
    let clean_id = validate_template_id(id)?;
    let tdir = templates_root(base_dir).join(&clean_id);
    let files_dir = tdir.join("files");
    if files_dir.is_dir() {
        fs::remove_dir_all(&files_dir)?;
    }
    fs::create_dir_all(&files_dir)?;

    let meta = TemplateMeta {
        id: clean_id.clone(),
        name: name.trim().to_string(),
        description: description.trim().to_string(),
        builtin,
        builtin_version: if builtin {
            RUST_WEB_APP_BUILTIN_VERSION
        } else {
            0
        },
    };
    fs::write(
        tdir.join("template.json"),
        serde_json::to_string_pretty(&meta)?,
    )?;

    let mut clean_files = HashMap::new();
    for (rel_str, content) in files {
        let rel_path = validate_rel_path(&rel_str)?;
        let dst = files_dir.join(&rel_path);
        if let Some(p) = dst.parent() {
            fs::create_dir_all(p)?;
        }
        fs::write(&dst, &content)?;
        clean_files.insert(rel_path.to_string_lossy().to_string(), content);
    }

    Ok(TemplateInfo {
        id: meta.id,
        name: meta.name,
        description: meta.description,
        builtin: meta.builtin,
        file_count: clean_files.len(),
        files: clean_files,
    })
}

pub fn save_custom_template(
    base_dir: &Path,
    id: &str,
    name: &str,
    description: &str,
    files: HashMap<String, String>,
) -> Result<TemplateInfo> {
    if id.trim() == "empty" {
        return Err(anyhow!("No se puede sobrescribir el template 'empty'."));
    }
    save_template_internal(base_dir, id, name, description, false, files)
}

pub fn delete_template(base_dir: &Path, id: &str) -> Result<()> {
    let clean_id = validate_template_id(id)?;
    if clean_id == "empty" {
        return Err(anyhow!("No se puede eliminar el template base 'empty'."));
    }
    let tdir = templates_root(base_dir).join(&clean_id);
    if !tdir.is_dir() {
        return Err(anyhow!("Template '{}' no encontrado.", clean_id));
    }
    fs::remove_dir_all(&tdir)?;
    Ok(())
}

fn collect_files_recursive(base: &Path, cur: &Path, out: &mut HashMap<String, String>) {
    if let Ok(entries) = fs::read_dir(cur) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_files_recursive(base, &p, out);
            } else if p.is_file() {
                if let Ok(rel) = p.strip_prefix(base) {
                    if let Ok(txt) = fs::read_to_string(&p) {
                        out.insert(rel.to_string_lossy().to_string(), txt);
                    }
                }
            }
        }
    }
}

pub fn list_templates(base_dir: &Path) -> Vec<TemplateInfo> {
    let root = templates_root(base_dir);
    let mut list = Vec::new();
    if let Ok(entries) = fs::read_dir(&root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let meta_path = p.join("template.json");
            if let Ok(raw) = fs::read_to_string(&meta_path) {
                if let Ok(meta) = serde_json::from_str::<TemplateMeta>(&raw) {
                    let mut files = HashMap::new();
                    let files_dir = p.join("files");
                    if files_dir.is_dir() {
                        collect_files_recursive(&files_dir, &files_dir, &mut files);
                    }
                    list.push(TemplateInfo {
                        id: meta.id,
                        name: meta.name,
                        description: meta.description,
                        builtin: meta.builtin,
                        file_count: files.len(),
                        files,
                    });
                }
            }
        }
    }
    list.sort_by(|a, b| {
        if a.id == "empty" {
            std::cmp::Ordering::Less
        } else if b.id == "empty" {
            std::cmp::Ordering::Greater
        } else {
            a.name.cmp(&b.name)
        }
    });
    list
}

pub fn apply_template(
    base_dir: &Path,
    template_id: &str,
    dest_dir: &Path,
    repo_name: &str,
    display_name: &str,
    owner: &str,
    license: &str,
) -> Result<usize> {
    let clean_id = template_id.trim();
    if clean_id.is_empty() || clean_id == "empty" {
        return Ok(0);
    }
    let files_dir = templates_root(base_dir).join(clean_id).join("files");
    if !files_dir.is_dir() {
        return Ok(0);
    }
    let mut files = HashMap::new();
    collect_files_recursive(&files_dir, &files_dir, &mut files);

    let effective_display = if display_name.trim().is_empty() {
        repo_name
    } else {
        display_name.trim()
    };
    let effective_owner = if owner.trim().is_empty() {
        "developer"
    } else {
        owner.trim()
    };
    let effective_license =
        if license.trim().is_empty() || license.trim().eq_ignore_ascii_case("none") {
            "MIT"
        } else {
            license.trim()
        };

    let mut written = 0usize;
    for (rel, content) in files {
        let dst = dest_dir.join(&rel);
        if dst.exists() {
            continue;
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        let rendered = content
            .replace("{{REPO_NAME}}", repo_name)
            .replace("{{DISPLAY_NAME}}", effective_display)
            .replace("{{OWNER}}", effective_owner)
            .replace("{{LICENSE}}", effective_license);
        fs::write(&dst, rendered)?;
        written += 1;
    }
    Ok(written)
}

pub fn write_license_file(dest_dir: &Path, license: &str, owner: &str) -> Result<bool> {
    let lic_path = dest_dir.join("LICENSE");
    if lic_path.exists() {
        return Ok(false);
    }
    let trimmed = license.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return Ok(false);
    }

    let year = chrono::Utc::now().format("%Y").to_string();
    let effective_owner = if owner.trim().is_empty() {
        "developer"
    } else {
        owner.trim()
    };

    let body = match trimmed.to_ascii_lowercase().as_str() {
        "mit" => format!(
            "MIT License\n\n\
Copyright (c) {year} {effective_owner}\n\n\
Permission is hereby granted, free of charge, to any person obtaining a copy\n\
of this software and associated documentation files (the \"Software\"), to deal\n\
in the Software without restriction, including without limitation the rights\n\
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n\
copies of the Software, and to permit persons to whom the Software is\n\
furnished to do so, subject to the following conditions:\n\n\
The above copyright notice and this permission notice shall be included in all\n\
copies or substantial portions of the Software.\n\n\
THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n\
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n\
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n\
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n\
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n\
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n\
SOFTWARE.\n"
        ),
        "apache-2.0" | "apache2" => format!(
            "SPDX-License-Identifier: Apache-2.0\n\n\
Apache License, Version 2.0\n\
Copyright {year} {effective_owner}\n\n\
Licensed under the Apache License, Version 2.0 (the \"License\");\n\
you may not use this file except in compliance with the License.\n\
You may obtain a copy of the License at:\n\n\
    https://www.apache.org/licenses/LICENSE-2.0\n\n\
Unless required by applicable law or agreed to in writing, software\n\
distributed under the License is distributed on an \"AS IS\" BASIS,\n\
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n\
See the License for the specific language governing permissions and\n\
limitations under the License.\n"
        ),
        "gpl-3.0-or-later" | "gpl-3.0" | "gpl3" => format!(
            "SPDX-License-Identifier: GPL-3.0-or-later\n\n\
GNU General Public License v3.0 or later\n\
Copyright (C) {year} {effective_owner}\n\n\
This program is free software: you can redistribute it and/or modify\n\
it under the terms of the GNU General Public License as published by\n\
the Free Software Foundation, either version 3 of the License, or\n\
(at your option) any later version.\n\n\
Full license text: https://www.gnu.org/licenses/gpl-3.0.html\n"
        ),
        other => {
            return Err(anyhow!(
                "Licencia no soportada '{}'. Usa MIT, Apache-2.0, GPL-3.0-or-later o none.",
                other
            ))
        }
    };

    fs::write(&lic_path, body)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("gitolorin_{}_{}_{}", prefix, std::process::id(), nanos));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_write_license_file_variants() {
        let d1 = temp_test_dir("lic_mit");
        assert!(write_license_file(&d1, "MIT", "edu").unwrap());
        let mit_txt = fs::read_to_string(d1.join("LICENSE")).unwrap();
        assert!(mit_txt.contains("MIT License"));
        assert!(mit_txt.contains("edu"));
        // Existing LICENSE should not be overwritten
        assert!(!write_license_file(&d1, "Apache-2.0", "other").unwrap());
        let _ = fs::remove_dir_all(&d1);

        let d2 = temp_test_dir("lic_apache");
        assert!(write_license_file(&d2, "Apache-2.0", "edu").unwrap());
        assert!(fs::read_to_string(d2.join("LICENSE"))
            .unwrap()
            .contains("Apache-2.0"));
        let _ = fs::remove_dir_all(&d2);

        let d3 = temp_test_dir("lic_gpl");
        assert!(write_license_file(&d3, "GPL-3.0-or-later", "edu").unwrap());
        assert!(fs::read_to_string(d3.join("LICENSE"))
            .unwrap()
            .contains("GPL-3.0-or-later"));
        let _ = fs::remove_dir_all(&d3);

        let d4 = temp_test_dir("lic_none");
        assert!(!write_license_file(&d4, "none", "edu").unwrap());
        assert!(!d4.join("LICENSE").exists());
        let _ = fs::remove_dir_all(&d4);
    }

    #[test]
    fn test_ensure_builtin_templates_upgrades_v0_and_preserves_custom() {
        let base = temp_test_dir("tpl_upgrade");
        let old_dir = templates_root(&base).join("rust-web-app");
        fs::create_dir_all(old_dir.join("files")).unwrap();
        fs::write(
            old_dir.join("template.json"),
            r#"{"id":"rust-web-app","name":"Old","description":"Old","builtin":true}"#,
        )
        .unwrap();
        fs::write(old_dir.join("files/Cargo.toml"), "old").unwrap();

        let mut custom_files = HashMap::new();
        custom_files.insert("README.md".to_string(), "custom".to_string());
        save_custom_template(&base, "my-custom", "My Custom", "desc", custom_files).unwrap();

        ensure_builtin_templates(&base).unwrap();

        let upgraded_meta: TemplateMeta =
            serde_json::from_str(&fs::read_to_string(old_dir.join("template.json")).unwrap())
                .unwrap();
        assert_eq!(upgraded_meta.builtin_version, RUST_WEB_APP_BUILTIN_VERSION);
        let cargo_toml = fs::read_to_string(old_dir.join("files/Cargo.toml")).unwrap();
        assert!(cargo_toml.contains("axum = \"0.8\""));
        assert!(cargo_toml.contains("rust-version = \"1.80\""));

        let custom_readme =
            fs::read_to_string(templates_root(&base).join("my-custom/files/README.md")).unwrap();
        assert_eq!(custom_readme, "custom");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_apply_template_renders_placeholders() {
        let base = temp_test_dir("tpl_apply");
        ensure_builtin_templates(&base).unwrap();
        let dest = temp_test_dir("tpl_dest");

        let written = apply_template(
            &base,
            "rust-web-app",
            &dest,
            "demo_app",
            "Demo App",
            "edu",
            "Apache-2.0",
        )
        .unwrap();
        assert!(written >= 4);
        let cargo = fs::read_to_string(dest.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("name = \"demo_app\""));
        assert!(cargo.contains("description = \"Demo App\""));
        assert!(cargo.contains("license = \"Apache-2.0\""));

        let main_rs = fs::read_to_string(dest.join("src/main.rs")).unwrap();
        assert!(main_rs.contains("demo_app.localhost"));
        assert!(main_rs.contains("SameSite=Strict"));

        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&dest);
    }
}
