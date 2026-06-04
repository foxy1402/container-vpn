#!/bin/sh
# wsgost-start.sh — supervises both gost-proxy (internal) and wsgost-bridge (public).
#
# Process layout inside the container:
#   gost-proxy   →  127.0.0.1:${GOST_INTERNAL_PORT}  (never exposed externally)
#   wsgost-bridge → 0.0.0.0:${WS_PORT}               (the single public port)
#
# If either process dies the other is killed and the container exits so the
# platform/orchestrator can restart it.

# Do NOT use set -e in a process supervisor: if a child exits non-zero the
# shell would bail out before we can kill the other child and propagate the
# exit code properly.  All critical error paths are checked explicitly below.

log() { printf '[wsgost] %s\n' "$*" >&2; }

# ── Port resolution ──────────────────────────────────────────────────────────
# GOST_INTERNAL_PORT: the loopback port gost-proxy listens on (default 18080)
GOST_INTERNAL_PORT="${GOST_INTERNAL_PORT:-18080}"

# WS_PORT: the public WebSocket port.
# Platforms like Railway / Render / Fly inject PORT; respect that first.
WS_PORT="${PORT:-${WS_PORT:-8080}}"

# ── Force GOST to bind loopback only ────────────────────────────────────────
export GOST_HOST=127.0.0.1
export GOST_PORT="$GOST_INTERNAL_PORT"

# Re-export resolved values so child processes pick them up
export GOST_INTERNAL_PORT
export WS_PORT

log "GOST internal : 127.0.0.1:${GOST_INTERNAL_PORT}"
log "WS bridge     : 0.0.0.0:${WS_PORT}  path=${WS_PATH:-/ws}"

# ── Start GOST proxy in background ──────────────────────────────────────────
/app/gost-proxy &
GOST_PID=$!

# Give GOST a moment to open its listener before the bridge dials it
sleep 2

if ! kill -0 "$GOST_PID" 2>/dev/null; then
    log "ERROR: gost-proxy failed to start (check GOST_USER / GOST_PASS)"
    exit 1
fi
log "gost-proxy ready (pid=$GOST_PID)"

# ── Start WebSocket bridge in background ────────────────────────────────────
/app/wsgost-bridge &
BRIDGE_PID=$!

log "wsgost-bridge ready (pid=$BRIDGE_PID)"

# ── Signal handling ──────────────────────────────────────────────────────────
cleanup() {
    log "Shutting down..."
    kill "$BRIDGE_PID" 2>/dev/null
    kill "$GOST_PID"   2>/dev/null
    wait "$BRIDGE_PID" "$GOST_PID" 2>/dev/null
    exit 0
}
trap cleanup TERM INT

# ── Wait for bridge; restart loop not needed — let platform restart container ─
wait "$BRIDGE_PID"
BRIDGE_EXIT=$?
log "wsgost-bridge exited (code=$BRIDGE_EXIT)"  # always reached now (no set -e)

kill "$GOST_PID" 2>/dev/null
wait "$GOST_PID" 2>/dev/null
exit "$BRIDGE_EXIT"
