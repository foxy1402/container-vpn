#!/bin/sh
# service-start.sh — generate service configuration and start the metrics agent.

set -eu

log() { printf '[metrics] %s\n' "$*" >&2; }

SERVICE_HOST="${SERVICE_HOST:-0.0.0.0}"
SERVICE_PORT="${PORT:-${SERVICE_PORT:-8080}}"
SERVICE_ENDPOINT="${SERVICE_ENDPOINT:-/api/v1/metrics}"
SERVICE_MODE="${SERVICE_MODE:-standard}"
LOG_LEVEL="${LOG_LEVEL:-warning}"

case "$SERVICE_MODE" in
    standard|enhanced) ;;
    *) log "SERVICE_MODE must be standard or enhanced (got: $SERVICE_MODE)"; exit 1 ;;
esac

if ! printf '%s' "$SERVICE_PORT" | grep -Eq '^[0-9]+$' || [ "$SERVICE_PORT" -lt 1 ] || [ "$SERVICE_PORT" -gt 65535 ]; then
    log "Invalid SERVICE_PORT: $SERVICE_PORT"
    exit 1
fi

if [ "${SERVICE_ENDPOINT#"/"}" = "$SERVICE_ENDPOINT" ]; then
    SERVICE_ENDPOINT="/$SERVICE_ENDPOINT"
fi

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'
}

case "$SERVICE_MODE" in
    standard)
        if [ -z "${SERVICE_TOKEN:-}" ]; then
            log "SERVICE_TOKEN must be set when SERVICE_MODE=standard"
            exit 1
        fi
        CLIENT_JSON=$(printf '{"id":"%s"}' "$(json_escape "$SERVICE_TOKEN")")
        SETTINGS_JSON=$(printf '"clients":[%s],"decryption":"none"' "$CLIENT_JSON")
        ;;
    enhanced)
        if [ -z "${SERVICE_CREDENTIAL:-}" ]; then
            log "SERVICE_CREDENTIAL must be set when SERVICE_MODE=enhanced"
            exit 1
        fi
        CLIENT_JSON=$(printf '{"password":"%s"}' "$(json_escape "$SERVICE_CREDENTIAL")")
        SETTINGS_JSON=$(printf '"clients":[%s]' "$CLIENT_JSON")
        ;;
esac

CONFIG_PATH="/tmp/service-config.json"
umask 077

cat > "$CONFIG_PATH" <<EOF
{
  "log": {
    "loglevel": "$(json_escape "$LOG_LEVEL")"
  },
  "inbounds": [
    {
      "listen": "$(json_escape "$SERVICE_HOST")",
      "port": $SERVICE_PORT,
      "protocol": "$SERVICE_MODE",
      "settings": {
        $SETTINGS_JSON
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$(json_escape "$SERVICE_ENDPOINT")"
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom" }
  ]
}
EOF

log "Starting metrics agent: mode=${SERVICE_MODE} endpoint=${SERVICE_HOST}:${SERVICE_PORT}${SERVICE_ENDPOINT}"
exec /usr/local/bin/cloud-metrics-agent -config "$CONFIG_PATH"
