let globalState = null;
let approveAllMode = false;
let registeredWebAuthnId = null;

document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  const selUnlock = document.getElementById("sel-repo-unlock");
  if (selUnlock) {
    selUnlock.addEventListener("change", () => {
      const grp = document.getElementById("grp-repo-pin");
      grp.classList.toggle("hidden", selUnlock.value !== "pin");
    });
  }
  const inpName = document.getElementById("inp-repo-name");
  const inpPath = document.getElementById("inp-repo-path");
  if (inpName && inpPath) {
    inpName.addEventListener("input", () => {
      const v = inpName.value.trim();
      if (!inpPath.dataset.touched) {
        inpPath.value = v ? `/home/edu/git/pub/${v}` : "";
      }
    });
    inpPath.addEventListener("input", () => {
      inpPath.dataset.touched = "1";
    });
  }
  refreshStatus();
  setInterval(refreshStatus, 5000);
});

function setupTabs() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const tabId = btn.getAttribute("data-tab");
      document.getElementById(`tab-${tabId}`).classList.add("active");
    });
  });
}

async function refreshStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    globalState = data;
    renderHeader(data);
    renderQueue(data.queue || []);
    renderRepos(data.repos || [], data.proxy_url);
    renderVaultStatus(data.vault, data.vcs_tools);
    renderAudit(data.audit_log || []);
  } catch (err) {
    console.error("Error refreshing gitOlorin status:", err);
  }
}

function renderHeader(data) {
  document.getElementById("pill-proxy").textContent = `Proxy Activo: ${data.proxy_url}`;
  const pillVault = document.getElementById("pill-vault");
  if (data.vault && data.vault.initialized) {
    pillVault.className = "pill pill-ok";
    pillVault.textContent = `🔐 Bóveda Sellada (${data.vault.github_username || "owner"})`;
  } else {
    pillVault.className = "pill pill-warn";
    pillVault.textContent = "⚠️ Bóveda Admin: Pendiente configurar";
  }

  const jjOk = data.vcs_tools && data.vcs_tools.jj_installed;
  document.getElementById("pill-vcs").textContent = jjOk
    ? `VCS: Jujutsu (jj) + Git listos`
    : `VCS: Git listo (jj auto-descargable)`;

  document.getElementById("badge-queue-count").textContent = data.counts.pending_total;
  document.getElementById("badge-repos-count").textContent = data.counts.repos_total;
  document.getElementById("lbl-ready-count").textContent = data.counts.ready_for_batch;
}

function renderQueue(queue) {
  const container = document.getElementById("queue-list");
  if (!queue.length) {
    container.innerHTML = `<div class="empty-state">🎉 No hay operaciones pendientes en la cola. Los agentes pueden hacer push a ramas secundarias o solicitar repos/MRs en cualquier momento.</div>`;
    return;
  }

  const kindLabels = {
    create_repo: "🆕 CREAR REPO EN GITHUB",
    merge_request: "🔀 MERGE REQUEST -> MAIN",
    protected_branch_push: "🛡️ PUSH A RAMA PROTEGIDA INTERCEPTADO",
    destructive_git_op: "⚠️ ACCIÓN DESTRUCTIVA RETENIDA",
  };

  container.innerHTML = queue
    .map((item) => {
      const isPending = item.status === "pending" || item.status === "approved_for_batch";
      const isMarked = item.status === "approved_for_batch";
      const statusBadge =
        item.status === "executed"
          ? `<span class="pill pill-ok">✅ Ejecutado</span>`
          : item.status === "rejected"
          ? `<span class="pill pill-warn">❌ Rechazado</span>`
          : item.status === "failed"
          ? `<span class="pill pill-warn">⚠️ Error: ${escapeHtml(item.error_message || "")}</span>`
          : isMarked
          ? `<span class="pill pill-ok">☑️ Marcado para Lote</span>`
          : `<span class="pill pill-neutral">⏳ Pendiente de revisión</span>`;

      const actionButtons = isPending
        ? `
          <button class="btn" onclick="viewItemDiff(${item.id})">🔍 Ver Diff</button>
          <button class="btn ${isMarked ? "btn-accent" : "btn-primary"}" onclick="toggleQueueItem(${item.id})">
            ${isMarked ? "☑️ Listo para Huella" : "Marcar Listo ✅"}
          </button>
          <button class="btn btn-danger" onclick="rejectQueueItem(${item.id})">Rechazar</button>
        `
        : `<button class="btn" onclick="viewItemDiff(${item.id})">🔍 Ver Detalle</button>`;

      return `
        <div class="queue-card ${isMarked ? "ready-batch" : ""}">
          <div>
            <div>
              <span class="q-badge q-${item.kind}">${kindLabels[item.kind] || item.kind}</span>
              <strong>#${item.id}</strong> · Repo: <span class="code-chip">${escapeHtml(item.repo_name)}</span>
              · ${statusBadge}
            </div>
            <div class="q-title">${escapeHtml(item.title)}</div>
            <div class="q-meta">${escapeHtml(item.description)}</div>
            <div class="q-meta" style="margin-top:4px;">
              Rama: <code>${escapeHtml(item.source_branch)}</code> &rarr; <code>${escapeHtml(item.target_branch)}</code>
            </div>
          </div>
          <div class="q-actions">
            ${actionButtons}
          </div>
        </div>
      `;
    })
    .join("");
}

function renderRepos(repos, proxyUrl) {
  const container = document.getElementById("repos-list");
  if (!repos.length) {
    container.innerHTML = `<div class="empty-state">Aún no has inicializado repositorios con gitOlorin. Usa el formulario de la izquierda o ejecuta <code>gitolorin init &lt;nombre&gt;</code>.</div>`;
    return;
  }

  container.innerHTML = repos
    .map((r) => {
      const syncBadge = r.github_synced
        ? `<span class="pill pill-ok">☁️ Sincronizado en GitHub</span>`
        : `<span class="pill pill-warn">⏳ Staging Local (En cola para GitHub)</span>`;
      return `
        <div class="repo-item">
          <div class="repo-item-head">
            <strong>📦 ${escapeHtml(r.name)}</strong>
            ${syncBadge}
          </div>
          <div class="q-meta">Workspace: <code>${escapeHtml(r.local_workspace_path)}</code></div>
          <div class="q-meta">Remote del Agente: <span class="code-chip">${proxyUrl}/git/${escapeHtml(r.name)}.git</span></div>
          <div class="q-meta">Modo VCS en <code>AGENTS.md</code>: <strong>${escapeHtml(r.vcs_mode.toUpperCase())}</strong> · Privado: ${r.private ? "Sí" : "No"}</div>
        </div>
      `;
    })
    .join("");
}

function renderVaultStatus(vault, vcs) {
  if (!vault) return;
  const ghUserInp = document.getElementById("inp-gh-user");
  if (ghUserInp && !ghUserInp.value && vault.github_username) {
    ghUserInp.value = vault.github_username;
  }

  const box = document.getElementById("env-status-box");
  box.innerHTML = `
    <div class="repo-item">
      <div><strong>Estado de Bóveda Admin:</strong> ${vault.initialized ? "✅ Encriptada con AES-256-GCM + Argon2id" : "⚠️ No inicializada"}</div>
      <div><strong>Huella / Biometría del Sistema:</strong> ${vault.os_bio_enabled ? "✅ Activa (fprintd / Polkit / TouchID / WinHello)" : "Solo PIN"}</div>
      <div><strong>Llave WebAuthn Navegador:</strong> ${vault.webauthn_registered ? "✅ Registrada" : "No registrada (Opcional)"}</div>
      <div><strong>Credencial Worker (Ramas secundarias):</strong> ${vault.has_worker_token ? "✅ Configurada" : "Modo Staging Local"}</div>
      <div><strong>Ramas Protegidas ("You Shall Not Pass!"):</strong> <code>${(vault.protected_branches || []).join(", ")}</code></div>
    </div>
    <div class="repo-item">
      <div><strong>Git:</strong> ${vcs && vcs.git_installed ? `✅ ${escapeHtml(vcs.git_version)}` : "❌ No detectado"}</div>
      <div><strong>Jujutsu (jj):</strong> ${vcs && vcs.jj_installed ? `✅ ${escapeHtml(vcs.jj_version)}` : "⏳ Se descargará automáticamente al crear un repo con modo jj"}</div>
    </div>
  `;
}

function renderAudit(logs) {
  const container = document.getElementById("audit-list");
  if (!logs.length) {
    container.innerHTML = `<div class="empty-state">Sin eventos de auditoría todavía.</div>`;
    return;
  }
  container.innerHTML = logs
    .map(
      (l) => `
      <div class="audit-row">
        <div>
          <span>${l.allowed ? "🟢" : "🛑"}</span>
          <strong>[${escapeHtml(l.repo_name)}]</strong>
          <code>${escapeHtml(l.action)}</code> por <em>${escapeHtml(l.actor)}</em>:
          ${escapeHtml(l.details)}
        </div>
        <div class="q-meta">${new Date(l.timestamp).toLocaleTimeString()}</div>
      </div>
    `
    )
    .join("");
}

async function handleVaultSetup(e) {
  e.preventDefault();
  const fb = document.getElementById("vault-feedback");
  fb.classList.remove("hidden");
  fb.textContent = "Encriptando bóveda con Argon2id + AES-256-GCM...";

  const payload = {
    github_username: document.getElementById("inp-gh-user").value,
    admin_pat: document.getElementById("inp-admin-pat").value,
    worker_token: document.getElementById("inp-worker-pat").value,
    pin: document.getElementById("inp-vault-pin").value,
    os_bio_enabled: document.getElementById("chk-os-bio").checked,
    webauthn_cred_id: registeredWebAuthnId,
    default_vcs: document.getElementById("sel-default-vcs").value,
  };

  const res = await fetch("/api/vault/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  fb.textContent = data.ok ? `✅ ${data.message}` : `❌ ${data.error}`;
  refreshStatus();
}

async function handleInitRepo(e) {
  e.preventDefault();
  const fb = document.getElementById("init-repo-feedback");
  fb.classList.remove("hidden");
  fb.textContent = "Configurando repositorio, proxy local y AGENTS.md...";

  const payload = {
    name: document.getElementById("inp-repo-name").value,
    workspace_path: document.getElementById("inp-repo-path").value || null,
    vcs_mode: document.getElementById("sel-repo-vcs").value,
    private: document.getElementById("sel-repo-priv").value === "true",
    unlock_mode: document.getElementById("sel-repo-unlock").value,
    pin: document.getElementById("inp-repo-pin").value || null,
  };

  const res = await fetch("/api/repos/init", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (data.ok) {
    fb.textContent = data.result.message;
    document.getElementById("inp-repo-name").value = "";
  } else {
    fb.textContent = `❌ ${data.error}`;
  }
  refreshStatus();
}

async function toggleQueueItem(id) {
  await fetch(`/api/queue/${id}/toggle`, { method: "POST" });
  refreshStatus();
}

async function rejectQueueItem(id) {
  await fetch(`/api/queue/${id}/reject`, { method: "POST" });
  refreshStatus();
}

async function viewItemDiff(id) {
  const modal = document.getElementById("modal-diff");
  const pre = document.getElementById("diff-modal-content");
  const title = document.getElementById("diff-modal-title");
  modal.classList.remove("hidden");
  pre.textContent = "Cargando diff desde el repositorio bare de staging...";

  const res = await fetch(`/api/queue/${id}/diff`);
  const data = await res.json();
  title.textContent = `#${data.id} — ${data.title}`;
  pre.textContent = data.diff || "Sin diferencias de código.";
}

function closeDiffModal() {
  document.getElementById("modal-diff").classList.add("hidden");
}

function openUnlockModal(allPending) {
  approveAllMode = allPending;
  document.getElementById("unlock-feedback").classList.add("hidden");
  document.getElementById("modal-unlock").classList.remove("hidden");
}

function closeUnlockModal() {
  document.getElementById("modal-unlock").classList.add("hidden");
}

async function submitBatchApproval(authMethod) {
  const fb = document.getElementById("unlock-feedback");
  fb.classList.remove("hidden");
  fb.textContent =
    authMethod === "os_bio"
      ? "指纹 Esperando confirmación biométrica del sistema (fprintd / Polkit / TouchID / WinHello)..."
      : "Desencriptando bóveda en RAM y ejecutando lote...";

  const payload = {
    auth_method: authMethod,
    pin: document.getElementById("inp-batch-pin").value || null,
    approve_all_pending: approveAllMode,
  };

  const res = await fetch("/api/queue/approve-batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (data.ok) {
    fb.textContent = `✅ ${data.message}`;
    setTimeout(() => {
      closeUnlockModal();
      refreshStatus();
    }, 1100);
  } else {
    fb.textContent = `❌ ${data.error}`;
  }
}

async function registerWebAuthnPasskey() {
  const lbl = document.getElementById("lbl-webauthn-status");
  if (!window.PublicKeyCredential) {
    lbl.textContent = "WebAuthn no disponible en este navegador.";
    return;
  }
  try {
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    const userId = new Uint8Array(16);
    window.crypto.getRandomValues(userId);

    const cred = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: "gitOlorin Local Bastion" },
        user: {
          id: userId,
          name: "edu@localhost",
          displayName: "gitOlorin Owner",
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          userVerification: "preferred",
        },
        timeout: 60000,
      },
    });
    if (cred && cred.id) {
      registeredWebAuthnId = cred.id;
      lbl.textContent = "✅ Passkey Biométrica registrada.";
    }
  } catch (err) {
    lbl.textContent = `Cancelado o no soportado: ${err.message}`;
  }
}

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
