# 🧙‍♂️ gitOlorin

**Local Git Bastion, Credential Broker & Biometric Approval Queue for AI Coding Agents.**  
*("You Shall Not Pass!" for `main`, `master`, `--force`, and destructive Git operations)*

---

## El Problema

Cuando trabajas con agentes de IA (Claude Code, Antigravity, Cursor, Codex, Aider):
1. **La Fricción de GitHub:** Crear un repositorio nuevo en GitHub, configurar reglas de protección (que GitHub bloquea en repositorios privados gratuitos) y generar un *Fine-Grained PAT* (que no tiene API de creación) toma varios minutos de clics manuales por proyecto.
2. **El Peligro del Token de Dueño:** Si por prisa le das un token general al agente, un error del modelo o un *indirect prompt injection* puede hacer `git push --force origin main`, reescribir tu historial o eliminar ramas.

---

## Cómo lo resuelve `gitOlorin`

`gitOlorin` es una aplicación multiplataforma portable (1 único binario compilado en Rust con servidor API, Proxy Git Smart HTTP y Frontend Web embebido) que actúa como **único bastión entre los agentes y tu cuenta de GitHub**:

1. **Doble Credencial + Bóveda Biométrica (`AES-256-GCM` + `Argon2id` + `ZeroizeOnDrop`):**
   - **Credencial 1 (Worker — Bajo privilegio):** El proxy local solo permite usarla para *fast-forward pushes* en ramas secundarias (`feat/*`, `agent/*`).
   - **Credencial 2 (Admin Vault — Alto privilegio):** Guardada encriptada en `~/.gitolorin/admin.vault`. **Nunca está desencriptada en RAM mientras los agentes trabajan.** Solo se desencripta durante un instante cuando apruebas la cola con tu **Huella del Sistema** (Linux `fprintd`/Polkit, macOS TouchID, Windows Hello) o tu PIN, y la memoria RAM se limpia con ceros (`Zeroize`) inmediatamente al terminar.
2. **Staging Local Instantáneo (Cero Bloqueos):**
   - Si un agente pide crear un repositorio proactivamente (`gitolorin init mi-repo`), `gitOlorin` crea al instante un repositorio *bare* local en `~/.gitolorin/staging/mi-repo.git`, configura un token local exclusivo para ese proyecto y deja en tu **Cola de Pendientes** la tarea de crearlo en GitHub.
   - El agente puede empezar a hacer commits, crear ramas y hacer `git push` de inmediato sin esperarte.
3. **Inyección Automática en `AGENTS.md` + Jujutsu (`jj`) / Worktrees:**
   - Al inicializar un repo, `gitOlorin` descarga o verifica **Jujutsu (`jj`)** (o configura `git worktree`) e inyecta automáticamente las instrucciones en `AGENTS.md` para que cualquier agente trabaje con `jj` y envíe Merge Requests a la cola.
4. **Inspección a Nivel de Protocolo Git (`git-receive-pack`):**
   - Si un agente intenta hacer `git push origin main`, `git push --force` o borrar una rama remota, el proxy de `gitOlorin` lo intercepta con *"🧙‍♂️ YOU SHALL NOT PASS!"*, aparca los commits de forma segura en una rama temporal y crea un ítem en tu **Cola de Aprobación**.
5. **Revisión en Lote ("1 Huella y Listo"):**
   - Cuando tienes tiempo, abres la Web UI (`http://127.0.0.1:9418`) o ejecutas `gitolorin status`, revisas los diffs, marcas los listos y apruebas todo el lote (creación de repos + merges a `main`) poniendo **una sola vez tu huella o PIN**.

---

## Uso Rápido (CLI & Web UI)

```bash
# 1. Levantar el Proxy Git Local + Interfaz Web (http://127.0.0.1:9418)
gitolorin serve --open

# 2. Configurar tu Bóveda Admin encriptada (también disponible desde la Web UI)
gitolorin setup-vault --github-user tu-usuario --admin-pat ghp_xxx --pin 1234 --os-bio

# 3. Inicializar un repositorio (Modo Agente / Staging Local instantáneo + Jujutsu en AGENTS.md)
gitolorin init nuevo-proyecto --vcs jj

# 4. Inicializar un repositorio (Modo Humano Interactivo: desbloquea con huella y crea en GitHub al instante)
gitolorin init nuevo-proyecto --vcs jj --bio

# 5. Crear un Merge Request en la cola hacia main
gitolorin mr --repo nuevo-proyecto --source feat/login --target main --title "Implementar OAuth2"

# 6. Ver pendientes y aprobar todo el lote con 1 sola Huella o PIN
gitolorin status
gitolorin approve --bio --all
```

## Licencia

MIT
