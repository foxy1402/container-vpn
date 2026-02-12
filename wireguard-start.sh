#!/bin/bash
set -euo pipefail

WG_DIR="/etc/wireguard"
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_SERVER_CIDR="${WG_SERVER_CIDR:-10.66.66.1/24}"
WG_DNS="${WG_DNS:-1.1.1.1}"
WG_CLIENT_COUNT="${WG_CLIENT_COUNT:-3}"
WG_CLIENT_PREFIX="${WG_CLIENT_PREFIX:-client}"
WG_CLIENT_ALLOWED_IPS="${WG_CLIENT_ALLOWED_IPS:-0.0.0.0/0,::/0}"
WG_ENDPOINT="${WG_ENDPOINT:-}"
WG_PERSISTENT_KEEPALIVE="${WG_PERSISTENT_KEEPALIVE:-25}"
WG_HEALTH_INTERVAL="${WG_HEALTH_INTERVAL:-15}"
WG_CONF="${WG_DIR}/${WG_INTERFACE}.conf"
WG_CLIENT_DIR="${WG_DIR}/clients"

log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*"
}

require_root() {
    if [ "${EUID}" -ne 0 ]; then
        log "ERROR: wireguard-start.sh must run as root"
        exit 1
    fi
}

require_tun_device() {
    if [ ! -c /dev/net/tun ]; then
        log "ERROR: /dev/net/tun is missing. Run container with --device=/dev/net/tun and --cap-add=NET_ADMIN"
        exit 1
    fi
}

ensure_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1
}

ensure_dependencies() {
    local missing=()
    for cmd in wg wg-quick ip iptables sysctl; do
        if ! ensure_cmd "$cmd"; then
            missing+=("$cmd")
        fi
    done

    if [ "${#missing[@]}" -eq 0 ]; then
        return
    fi

    if ! ensure_cmd apt-get; then
        log "ERROR: Missing dependencies (${missing[*]}) and apt-get is unavailable"
        exit 1
    fi

    log "Installing missing dependencies: ${missing[*]}"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        wireguard-tools iproute2 iptables procps
    rm -rf /var/lib/apt/lists/*
}

validate_inputs() {
    if ! [[ "$WG_PORT" =~ ^[0-9]+$ ]] || [ "$WG_PORT" -lt 1 ] || [ "$WG_PORT" -gt 65535 ]; then
        log "ERROR: WG_PORT must be a valid port (1-65535)"
        exit 1
    fi

    if ! [[ "$WG_CLIENT_COUNT" =~ ^[0-9]+$ ]] || [ "$WG_CLIENT_COUNT" -lt 1 ] || [ "$WG_CLIENT_COUNT" -gt 250 ]; then
        log "ERROR: WG_CLIENT_COUNT must be 1-250"
        exit 1
    fi

    if ! [[ "$WG_HEALTH_INTERVAL" =~ ^[0-9]+$ ]] || [ "$WG_HEALTH_INTERVAL" -lt 5 ]; then
        log "ERROR: WG_HEALTH_INTERVAL must be >= 5"
        exit 1
    fi

    if ! [[ "$WG_SERVER_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        log "ERROR: WG_SERVER_CIDR must look like 10.66.66.1/24"
        exit 1
    fi
    if [ "${WG_SERVER_CIDR##*/}" -ne 24 ]; then
        log "ERROR: WG_SERVER_CIDR currently supports /24 only"
        exit 1
    fi

    local server_octet
    server_octet="$(echo "${WG_SERVER_CIDR%%/*}" | awk -F. '{print $4}')"
    if [ "$server_octet" -lt 1 ] || [ "$server_octet" -gt 254 ]; then
        log "ERROR: WG_SERVER_CIDR host octet must be between 1 and 254"
        exit 1
    fi
}

get_public_endpoint() {
    if [ -n "$WG_ENDPOINT" ]; then
        echo "$WG_ENDPOINT"
        return
    fi

    local detected_ip
    if ensure_cmd curl; then
        detected_ip="$(curl -4fsS --max-time 5 https://api.ipify.org || true)"
    elif ensure_cmd wget; then
        detected_ip="$(wget -4qO- --timeout=5 https://api.ipify.org || true)"
    fi

    if [ -n "$detected_ip" ] && [[ "$detected_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "${detected_ip}:${WG_PORT}"
        return
    fi

    detected_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')"
    if [ -z "$detected_ip" ]; then
        detected_ip="$(hostname -i 2>/dev/null | awk '{print $1}')"
    fi

    if [ -z "$detected_ip" ]; then
        log "ERROR: Could not detect public endpoint. Set WG_ENDPOINT manually (ip-or-host:port)"
        exit 1
    fi

    echo "${detected_ip}:${WG_PORT}"
}

setup_dirs() {
    mkdir -p "$WG_DIR" "$WG_CLIENT_DIR"
    chmod 700 "$WG_DIR" "$WG_CLIENT_DIR"
}

enable_ip_forwarding() {
    log "Enabling IPv4 forwarding"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    mkdir -p /etc/sysctl.d
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard-ipforward.conf
}

ensure_server_keys() {
    if [ ! -s "${WG_DIR}/server_private.key" ]; then
        log "Generating server private key"
        umask 077
        wg genkey > "${WG_DIR}/server_private.key"
    fi

    if [ ! -s "${WG_DIR}/server_public.key" ]; then
        log "Generating server public key"
        wg pubkey < "${WG_DIR}/server_private.key" > "${WG_DIR}/server_public.key"
    fi

    chmod 600 "${WG_DIR}/server_private.key"
    chmod 644 "${WG_DIR}/server_public.key"
}

get_default_interface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

write_base_server_config() {
    local private_key
    private_key="$(cat "${WG_DIR}/server_private.key")"

    local outbound_if
    outbound_if="$(get_default_interface)"
    if [ -z "$outbound_if" ]; then
        log "ERROR: Failed to detect outbound interface for NAT"
        exit 1
    fi

    cat > "$WG_CONF" <<EOF
[Interface]
Address = ${WG_SERVER_CIDR}
ListenPort = ${WG_PORT}
PrivateKey = ${private_key}
SaveConfig = false
PostUp = iptables -A FORWARD -i ${WG_INTERFACE} -j ACCEPT; iptables -A FORWARD -o ${WG_INTERFACE} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${outbound_if} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_INTERFACE} -j ACCEPT; iptables -D FORWARD -o ${WG_INTERFACE} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${outbound_if} -j MASQUERADE
EOF

    chmod 600 "$WG_CONF"
}

append_peer_if_missing() {
    local client_name="$1"
    local client_public_key="$2"
    local client_ip="$3"
    local client_psk="$4"

    if grep -q "# CLIENT: ${client_name}" "$WG_CONF" 2>/dev/null; then
        return
    fi

    cat >> "$WG_CONF" <<EOF

# CLIENT: ${client_name}
[Peer]
PublicKey = ${client_public_key}
PresharedKey = ${client_psk}
AllowedIPs = ${client_ip}/32
EOF
}

extract_prefix_24() {
    local ip_cidr="$1"
    local ip
    ip="${ip_cidr%%/*}"
    echo "$ip" | awk -F. '{print $1"."$2"."$3}'
}

extract_host_octet() {
    local ip_cidr="$1"
    local ip
    ip="${ip_cidr%%/*}"
    echo "$ip" | awk -F. '{print $4}'
}

generate_clients() {
    local server_public_key endpoint subnet_prefix server_host_octet
    server_public_key="$(cat "${WG_DIR}/server_public.key")"
    endpoint="$(get_public_endpoint)"
    subnet_prefix="$(extract_prefix_24 "$WG_SERVER_CIDR")"
    server_host_octet="$(extract_host_octet "$WG_SERVER_CIDR")"
    local current_octet=2

    for i in $(seq 1 "$WG_CLIENT_COUNT"); do
        local client_name="${WG_CLIENT_PREFIX}${i}"
        while [ "$current_octet" -eq "$server_host_octet" ] || [ "$current_octet" -eq 255 ]; do
            current_octet=$((current_octet + 1))
        done
        local client_ip="${subnet_prefix}.${current_octet}"
        current_octet=$((current_octet + 1))
        local client_dir="${WG_CLIENT_DIR}/${client_name}"

        mkdir -p "$client_dir"
        chmod 700 "$client_dir"

        if [ ! -s "${client_dir}/private.key" ]; then
            umask 077
            wg genkey > "${client_dir}/private.key"
            wg pubkey < "${client_dir}/private.key" > "${client_dir}/public.key"
            wg genpsk > "${client_dir}/psk.key"
            chmod 600 "${client_dir}/private.key" "${client_dir}/psk.key"
            chmod 644 "${client_dir}/public.key"
        fi

        local client_private_key client_public_key client_psk
        client_private_key="$(cat "${client_dir}/private.key")"
        client_public_key="$(cat "${client_dir}/public.key")"
        client_psk="$(cat "${client_dir}/psk.key")"

        append_peer_if_missing "$client_name" "$client_public_key" "$client_ip" "$client_psk"

        cat > "${client_dir}/${client_name}.conf" <<EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${client_ip}/32
DNS = ${WG_DNS}

[Peer]
PublicKey = ${server_public_key}
PresharedKey = ${client_psk}
Endpoint = ${endpoint}
AllowedIPs = ${WG_CLIENT_ALLOWED_IPS}
PersistentKeepalive = ${WG_PERSISTENT_KEEPALIVE}
EOF

        chmod 600 "${client_dir}/${client_name}.conf"
    done

    log "Client profiles generated in ${WG_CLIENT_DIR}"
}

start_or_reload_wg() {
    if wg show "$WG_INTERFACE" >/dev/null 2>&1; then
        log "WireGuard interface exists, reloading config"
        wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE") || {
            log "syncconf failed, restarting interface"
            wg-quick down "$WG_INTERFACE" || true
            wg-quick up "$WG_INTERFACE"
        }
    else
        log "Starting WireGuard interface ${WG_INTERFACE}"
        wg-quick up "$WG_INTERFACE"
    fi
}

shutdown_wg() {
    log "Shutting down WireGuard interface ${WG_INTERFACE}"
    wg-quick down "$WG_INTERFACE" >/dev/null 2>&1 || true
}

self_heal_loop() {
    while true; do
        sleep "$WG_HEALTH_INTERVAL"
        if ! wg show "$WG_INTERFACE" >/dev/null 2>&1; then
            log "Interface ${WG_INTERFACE} is down, attempting recovery"
            wg-quick up "$WG_INTERFACE" || log "Recovery attempt failed"
        fi
    done
}

main() {
    require_root
    require_tun_device
    ensure_dependencies
    validate_inputs
    setup_dirs
    enable_ip_forwarding
    ensure_server_keys
    write_base_server_config
    generate_clients
    start_or_reload_wg

    trap 'shutdown_wg; exit 0' INT TERM

    log "WireGuard server is running on ${WG_INTERFACE}:${WG_PORT}"
    log "Clients: ${WG_CLIENT_COUNT}, output: ${WG_CLIENT_DIR}"
    self_heal_loop
}

main "$@"
