#!/usr/bin/env bash
set -euo pipefail

# Arranca gitOlorin en primer plano (sin tray ni segundo plano) para acceder por Tailscale.
# Pulsa Ctrl+C para detener el servidor y liberar los recursos inmediatamente.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-9418}"
HOST_SHORT="${ALLOW_HOST:-$(hostname -s 2>/dev/null || hostname)}"

# Localizar binario de gitolorin
if [[ -n "${GITOLORIN_BIN:-}" && -x "${GITOLORIN_BIN}" ]]; then
  BIN="$GITOLORIN_BIN"
elif [[ -x "$SCRIPT_DIR/target/release/gitolorin" ]]; then
  BIN="$SCRIPT_DIR/target/release/gitolorin"
elif command -v gitolorin >/dev/null 2>&1; then
  BIN="$(command -v gitolorin)"
elif [[ -x "$HOME/.local/bin/gitolorin" ]]; then
  BIN="$HOME/.local/bin/gitolorin"
else
  echo "❌ No se encontró el binario 'gitolorin'. Compílalo primero con: cargo build --release" >&2
  exit 1
fi

# Detectar CLI de Tailscale (Linux o macOS app bundle)
TAILSCALE_BIN=""
if command -v tailscale >/dev/null 2>&1; then
  TAILSCALE_BIN="$(command -v tailscale)"
elif [[ -x "/Applications/Tailscale.app/Contents/MacOS/Tailscale" ]]; then
  TAILSCALE_BIN="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
fi

TS_IP=""
if [[ -n "$TAILSCALE_BIN" ]]; then
  TS_IP="$("$TAILSCALE_BIN" ip -4 2>/dev/null | head -n1 || true)"
fi

if [[ -z "${BIND_ADDR:-}" ]]; then
  if [[ -n "$TS_IP" ]]; then
    BIND_ADDR="$TS_IP"
  else
    BIND_ADDR="0.0.0.0"
    echo "⚠️  No se detectó IP de Tailscale; escuchando en 0.0.0.0:$PORT (puedes fijar BIND_ADDR=<ip>)." >&2
  fi
fi

ALLOW_ARGS=(--allow-host "$HOST_SHORT")
if [[ -n "$TS_IP" && "$TS_IP" != "$BIND_ADDR" ]]; then
  ALLOW_ARGS+=(--allow-host "$TS_IP")
fi

HOST_FQDN="$(hostname -f 2>/dev/null || true)"
if [[ -n "$HOST_FQDN" && "$HOST_FQDN" != "$HOST_SHORT" ]]; then
  ALLOW_ARGS+=(--allow-host "$HOST_FQDN")
fi

if [[ -n "${EXTRA_ALLOW_HOSTS:-}" ]]; then
  IFS=',' read -ra _extra <<< "$EXTRA_ALLOW_HOSTS"
  for h in "${_extra[@]}"; do
    h="${h// /}"
    [[ -n "$h" ]] && ALLOW_ARGS+=(--allow-host "$h")
  done
fi

echo "🧙‍♂️ Iniciando gitOlorin Web UI en primer plano (sin tray)..."
echo "   ├─ Abrir en Tailscale : http://${HOST_SHORT}:${PORT}"
if [[ -n "$TS_IP" ]]; then
  echo "   ├─ IP Tailscale       : http://${TS_IP}:${PORT}"
fi
echo "   └─ Detener y liberar  : pulsa Ctrl+C"
echo ""

exec "$BIN" --port "$PORT" serve --no-tray --bind "$BIND_ADDR" "${ALLOW_ARGS[@]}"
