#!/bin/bash
set -e

# WireGuard Configuration Script
# Generates WireGuard config from environment variables

CONFIG_FILE="/etc/wireguard/wg0.conf"
PRIVATE_KEY="${WG_PRIVATE_KEY}"
PEER_PUBLIC_KEY="${WG_PEER_PUBLIC_KEY}"
ADDRESS="${WG_ADDRESS:-10.0.0.2/24}"
ENDPOINT="${WG_ENDPOINT}"
DNS="${WG_DNS:-1.1.1.1}"
ALLOWED_IPS="${WG_ALLOWED_IPS:-0.0.0.0/0}"
PERSISTENT_KEEPALIVE="${WG_KEEPALIVE:-25}"

echo "Configuring WireGuard..."

# Check required variables
if [ -z "$PRIVATE_KEY" ]; then
    echo "ERROR: WG_PRIVATE_KEY not set"
    echo "Generate with: wg genkey"
    exit 1
fi

if [ -z "$PEER_PUBLIC_KEY" ]; then
    echo "ERROR: WG_PEER_PUBLIC_KEY not set"
    exit 1
fi

if [ -z "$ENDPOINT" ]; then
    echo "ERROR: WG_ENDPOINT not set (format: server.com:51820)"
    exit 1
fi

# Create config directory
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# Generate config file
cat > "$CONFIG_FILE" <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $ADDRESS
DNS = $DNS

[Peer]
PublicKey = $PEER_PUBLIC_KEY
Endpoint = $ENDPOINT
AllowedIPs = $ALLOWED_IPS
PersistentKeepalive = $PERSISTENT_KEEPALIVE
EOF

chmod 600 "$CONFIG_FILE"

echo "✓ WireGuard configuration created"
echo "Starting WireGuard..."

# Start WireGuard
exec wg-quick up wg0
