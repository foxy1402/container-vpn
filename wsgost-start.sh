#!/bin/sh
# wsgost-start.sh — generate Xray config from env vars and start the WS proxy.

set -eu

log() { printf '[wsgost] %s\n' "$*" >&2; }

WS_HOST="${WS_HOST:-0.0.0.0}"
WS_PORT="${PORT:-${WS_PORT:-8080}}"
WS_PATH="${WS_PATH:-/ws}"
WS_PROTOCOL="${WS_PROTOCOL:-vless}"
XRAY_LOG_LEVEL="${XRAY_LOG_LEVEL:-warning}"

case "$WS_PROTOCOL" in
    vless|trojan) ;;
    *) log "WS_PROTOCOL must be vless or trojan (got: $WS_PROTOCOL)"; exit 1 ;;
esac

if ! printf '%s' "$WS_PORT" | grep -Eq '^[0-9]+$' || [ "$WS_PORT" -lt 1 ] || [ "$WS_PORT" -gt 65535 ]; then
    log "Invalid WS_PORT: $WS_PORT"
    exit 1
fi

if [ "${WS_PATH#"/"}" = "$WS_PATH" ]; then
    WS_PATH="/$WS_PATH"
fi

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'
}

case "$WS_PROTOCOL" in
    vless)
        if [ -z "${VLESS_UUID:-}" ]; then
            log "VLESS_UUID must be set when WS_PROTOCOL=vless"
            exit 1
        fi
        CLIENT_JSON=$(printf '{"id":"%s"}' "$(json_escape "$VLESS_UUID")")
        SETTINGS_JSON=$(printf '"clients":[%s],"decryption":"none"' "$CLIENT_JSON")
        ;;
    trojan)
        if [ -z "${TROJAN_PASSWORD:-}" ]; then
            log "TROJAN_PASSWORD must be set when WS_PROTOCOL=trojan"
            exit 1
        fi
        CLIENT_JSON=$(printf '{"password":"%s"}' "$(json_escape "$TROJAN_PASSWORD")")
        SETTINGS_JSON=$(printf '"clients":[%s]' "$CLIENT_JSON")
        ;;
esac

CONFIG_PATH="/tmp/xray-config.json"
umask 077

cat > "$CONFIG_PATH" <<EOF
{
  "log": {
    "loglevel": "$(json_escape "$XRAY_LOG_LEVEL")"
  },
  "inbounds": [
    {
      "listen": "$(json_escape "$WS_HOST")",
      "port": $WS_PORT,
      "protocol": "$WS_PROTOCOL",
      "settings": {
        $SETTINGS_JSON
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$(json_escape "$WS_PATH")"
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom" }
  ]
}
EOF

log "Starting Xray: ${WS_PROTOCOL} over WS on ${WS_HOST}:${WS_PORT} (path=${WS_PATH})"
exec /usr/local/bin/xray -config "$CONFIG_PATH"
