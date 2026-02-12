

```markdown
# Development Guide: Debian 13 Minimal Container Environment

## Current Environment Analysis

**Base OS**: Debian 13 (trixie) - minimal container
**Kernel**: 5.15.0-164-generic (x86_64)
**Package Manager**: apt (Debian)

## Current Capabilities

✅ **Available**:
- Basic shell utilities
- Network interface: `eth0` (active), `lo`

❌ **Missing** (need installation):
- Python 3 (not installed by default)
- Network tools (`ip`, `netstat`, `ss`)
- Development tools (`git`, `gcc`, `curl`, `wget`)
- VPN/proxy dependencies

## Image Build Requirements

### 1. SOCKS5 Proxy Image
**Purpose**: SOCKS5 network proxy server
**Dependencies**:
- Python 3
- pip package manager
- Network tools

**Implementation**:
```dockerfile
FROM debian:13-slim
RUN apt update && apt install -y python3 python3-pip iproute2
COPY socks5_proxy.py /app/
WORKDIR /app
RUN pip3 install requests
CMD ["python3", "socks5_proxy.py"]
```

### 2. WireGuard VPN Image  
**Purpose**: WireGuard VPN server/client
**Dependencies**:
- wireguard-tools
- TUN device support (`/dev/net/tun`)
- Kernel modules (host must have WireGuard support)

**Implementation**:
```dockerfile
FROM debian:13-slim
RUN apt update && apt install -y wireguard-tools resolvconf
RUN mkdir -p /dev/net && mknod /dev/net/tun c 10 200
COPY wg0.conf /etc/wireguard/
CMD ["wg-quick", "up", "wg0"]
```

### 3. HTTP Proxy Image
**Purpose**: HTTP forwarding proxy
**Dependencies**:
- Python 3
- HTTP proxy library

**Implementation**:
```dockerfile
FROM debian:13-slim
RUN apt update && apt install -y python3 python3-pip
COPY http-proxy.py /app/
WORKDIR /app
RUN pip3 install proxy.py
CMD ["python3", "http-proxy.py"]
```

## Key Constraints

1. **Minimal Base**: Start with `debian:13-slim` for small image size
2. **Network Isolation**: Containers may have limited network capabilities
3. **Privilege Requirements**: WireGuard needs `--cap-add=NET_ADMIN --device=/dev/net/tun`
4. **Port Access**: Ensure required ports are exposed and available

## Development Commands

**Install essential tools**:
```bash
apt update
apt install -y iproute2 net-tools curl wget python3 python3-pip
```

**Test network capabilities**:
```bash
cat /proc/net/dev
```

**Check Python availability**:
```bash
which python3
python3 --version
```

## Recommendations

1. **Python Implementation**: Modify existing Python SOCKS5 proxy instead of Go version
2. **Image Tagging**: Use descriptive tags (`:socks5`, `:wireguard`, `:http-proxy`)
3. **Minimal Dependencies**: Install only required packages to keep images small
4. **Health Checks**: Implement container health checks for proxy services

This environment requires installing Python 3 and network tools before deploying proxy services.
```