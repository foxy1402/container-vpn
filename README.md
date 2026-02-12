# Cloud-Ready Proxy Images

> **Multi-Service Docker Images** for Cloud Deployment (Claw Cloud, Kubernetes, etc.)

Production-ready proxy services packaged as **separate Docker images** with unique tags. Each image is optimized for cloud platforms where **one pod runs one service**.

---

## 📦 Available Images

| Service | Tag | Port | Purpose |
|---------|-----|------|---------|
| **SOCKS5 Proxy** | `:socks5` | 1080 | Full SOCKS5 proxy with auth |
| **HTTP Proxy** | `:http-proxy` | 8080 | HTTP/HTTPS proxy with auth |
| **WireGuard VPN** | `:wireguard` | - | VPN tunnel client |

---

## 🚀 Quick Start

### Build All Images

```bash
# Clone or download this repository
cd proxy-images

# Build all images at once
./build-all.sh

# Or build individually
docker build -f Dockerfile -t proxy:socks5 .
docker build -f Dockerfile.http -t proxy:http-proxy .
docker build -f Dockerfile.wireguard -t proxy:wireguard .
```

### Push to Registry

```bash
# Tag for your registry
docker tag proxy:socks5 ghcr.io/yourusername/proxy:socks5
docker tag proxy:http-proxy ghcr.io/yourusername/proxy:http-proxy
docker tag proxy:wireguard ghcr.io/yourusername/proxy:wireguard

# Push to GitHub Container Registry
docker push ghcr.io/yourusername/proxy:socks5
docker push ghcr.io/yourusername/proxy:http-proxy
docker push ghcr.io/yourusername/proxy:wireguard

# Or use Docker Hub
docker tag proxy:socks5 yourusername/proxy:socks5
docker push yourusername/proxy:socks5
```

---

## 🌐 Deploy on Claw Cloud

### 1. SOCKS5 Proxy

**Image**: `ghcr.io/yourusername/proxy:socks5`

**Environment Variables**:
```yaml
SOCKS5_HOST: "0.0.0.0"
SOCKS5_PORT: "1080"
SOCKS5_USER: "your-username"
SOCKS5_PASS: "your-secure-password"
SOCKS5_MAX_CONN: "50"
SOCKS5_TIMEOUT: "30"
SOCKS5_IDLE_TIMEOUT: "300"
```

**Port Mapping**: `1080:1080`

**Usage**:
```bash
curl -x socks5://your-username:your-password@your-pod-url:1080 https://ifconfig.me
```

---

### 2. HTTP Proxy

**Image**: `ghcr.io/yourusername/proxy:http-proxy`

**Environment Variables**:
```yaml
HTTP_PROXY_HOST: "0.0.0.0"
HTTP_PROXY_PORT: "8080"
HTTP_PROXY_USER: "your-username"
HTTP_PROXY_PASS: "your-secure-password"
HTTP_MAX_CONN: "50"
```

**Port Mapping**: `8080:8080`

**Usage**:
```bash
# HTTP
curl -x http://your-username:your-password@your-pod-url:8080 http://example.com

# HTTPS (CONNECT method)
curl -x http://your-username:your-password@your-pod-url:8080 https://example.com
```

---

### 3. WireGuard VPN

**Image**: `ghcr.io/yourusername/proxy:wireguard`

**Special Requirements**:
- ⚠️ Needs `NET_ADMIN` capability
- ⚠️ Needs `/dev/net/tun` device

**Environment Variables**:
```yaml
WG_PRIVATE_KEY: "your-private-key"
WG_PEER_PUBLIC_KEY: "server-public-key"
WG_ADDRESS: "10.0.0.2/24"
WG_ENDPOINT: "vpn.example.com:51820"
WG_DNS: "1.1.1.1"
WG_ALLOWED_IPS: "0.0.0.0/0"
WG_KEEPALIVE: "25"
```

**Generate Keys**:
```bash
# Generate private key
wg genkey

# Generate public key from private
echo "YOUR_PRIVATE_KEY" | wg pubkey
```

**Deploy Command** (if Claw supports):
```bash
--cap-add=NET_ADMIN --device=/dev/net/tun
```

**Note**: Not all cloud platforms support WireGuard (requires kernel module). Check Claw Cloud documentation.

---

## 🔧 Local Testing

### Test SOCKS5

```bash
# Run container
docker run -d \
  --name test-socks5 \
  -p 1080:1080 \
  -e SOCKS5_USER=testuser \
  -e SOCKS5_PASS=testpass \
  proxy:socks5

# Test connection
curl -x socks5://testuser:testpass@localhost:1080 https://ifconfig.me

# View logs
docker logs test-socks5 -f

# Stop
docker stop test-socks5 && docker rm test-socks5
```

### Test HTTP Proxy

```bash
# Run container
docker run -d \
  --name test-http \
  -p 8080:8080 \
  -e HTTP_PROXY_USER=testuser \
  -e HTTP_PROXY_PASS=testpass \
  proxy:http-proxy

# Test HTTP
curl -x http://testuser:testpass@localhost:8080 http://httpbin.org/ip

# Test HTTPS
curl -x http://testuser:testpass@localhost:8080 https://ifconfig.me

# View logs
docker logs test-http -f

# Stop
docker stop test-http && docker rm test-http
```

### Test WireGuard

```bash
# Generate test keys
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

# Run container (requires privileges)
docker run -d \
  --name test-wg \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -e WG_PRIVATE_KEY="$PRIVATE_KEY" \
  -e WG_PEER_PUBLIC_KEY="server-public-key-here" \
  -e WG_ENDPOINT="vpn.server.com:51820" \
  proxy:wireguard

# Check status
docker exec test-wg wg show

# View logs
docker logs test-wg -f

# Stop
docker stop test-wg && docker rm test-wg
```

---

## 📋 Environment Variables Reference

### SOCKS5 Proxy (`:socks5`)

| Variable | Default | Description |
|----------|---------|-------------|
| `SOCKS5_HOST` | `0.0.0.0` | Bind address |
| `SOCKS5_PORT` | `1080` | Listen port |
| `SOCKS5_USER` | `user` | Authentication username |
| `SOCKS5_PASS` | `pass` | Authentication password |
| `SOCKS5_MAX_CONN` | `50` | Max concurrent connections |
| `SOCKS5_TIMEOUT` | `30` | Connection timeout (seconds) |
| `SOCKS5_IDLE_TIMEOUT` | `300` | Idle timeout (seconds) |

### HTTP Proxy (`:http-proxy`)

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_PROXY_HOST` | `0.0.0.0` | Bind address |
| `HTTP_PROXY_PORT` | `8080` | Listen port |
| `HTTP_PROXY_USER` | `user` | Authentication username |
| `HTTP_PROXY_PASS` | `pass` | Authentication password |
| `HTTP_MAX_CONN` | `50` | Max concurrent connections |

### WireGuard VPN (`:wireguard`)

| Variable | Required | Description |
|----------|----------|-------------|
| `WG_PRIVATE_KEY` | ✅ Yes | Your private key |
| `WG_PEER_PUBLIC_KEY` | ✅ Yes | Server public key |
| `WG_ENDPOINT` | ✅ Yes | Server endpoint (ip:port) |
| `WG_ADDRESS` | No | Interface address (default: 10.0.0.2/24) |
| `WG_DNS` | No | DNS server (default: 1.1.1.1) |
| `WG_ALLOWED_IPS` | No | Allowed IPs (default: 0.0.0.0/0) |
| `WG_KEEPALIVE` | No | Keepalive interval (default: 25) |

---

## 🏗️ Image Details

### Base Image
All images use `debian:13-slim` for minimal size.

### Image Sizes (Approximate)
- **SOCKS5**: ~80 MB
- **HTTP**: ~60 MB
- **WireGuard**: ~70 MB

### Security Features
✅ Non-root user (UID 1000)  
✅ Minimal dependencies  
✅ No unnecessary packages  
✅ Built-in health checks  
✅ Authentication required  

### Health Checks
All images include Docker health checks:
- **Interval**: 30 seconds
- **Timeout**: 10 seconds
- **Start Period**: 10 seconds
- **Retries**: 3

---

## 📝 Claw Cloud Deployment Guide

### Step 1: Build and Push Images

```bash
# Set your registry
export REGISTRY="ghcr.io"
export NAMESPACE="yourusername"

# Login to registry
echo "YOUR_GITHUB_TOKEN" | docker login ghcr.io -u yourusername --password-stdin

# Build all
./build-all.sh

# Push all
docker push ghcr.io/yourusername/proxy:socks5
docker push ghcr.io/yourusername/proxy:http-proxy
docker push ghcr.io/yourusername/proxy:wireguard
```

### Step 2: Deploy on Claw Cloud

#### For SOCKS5 Proxy:

1. Create new pod/app
2. **Image**: `ghcr.io/yourusername/proxy:socks5`
3. **Port**: `1080`
4. **Environment**:
   ```
   SOCKS5_USER=your-secure-username
   SOCKS5_PASS=your-secure-password
   ```
5. Deploy

#### For HTTP Proxy:

1. Create new pod/app
2. **Image**: `ghcr.io/yourusername/proxy:http-proxy`
3. **Port**: `8080`
4. **Environment**:
   ```
   HTTP_PROXY_USER=your-secure-username
   HTTP_PROXY_PASS=your-secure-password
   ```
5. Deploy

#### For WireGuard (if supported):

1. Create new pod/app
2. **Image**: `ghcr.io/yourusername/proxy:wireguard`
3. **Capabilities**: `NET_ADMIN` (check if Claw supports)
4. **Devices**: `/dev/net/tun` (check if Claw supports)
5. **Environment**:
   ```
   WG_PRIVATE_KEY=your-generated-private-key
   WG_PEER_PUBLIC_KEY=server-public-key
   WG_ENDPOINT=vpn.server.com:51820
   ```
6. Deploy

### Step 3: Test Deployment

Get your pod URL from Claw Cloud, then:

```bash
# Test SOCKS5
curl -x socks5://user:pass@your-pod.claw.cloud:1080 https://ifconfig.me

# Test HTTP
curl -x http://user:pass@your-pod.claw.cloud:8080 https://ifconfig.me
```

---

## 🔒 Security Best Practices

1. **Change Default Credentials**
   - Never use `user`/`pass` in production
   - Use strong passwords (20+ characters)

2. **Use Secrets Management**
   - Store credentials as secrets in Claw Cloud
   - Don't hardcode in deployment configs

3. **Network Isolation**
   - Use private networks when possible
   - Restrict access with IP allowlists

4. **Regular Updates**
   - Rebuild images monthly
   - Monitor for security updates

5. **Logging**
   - Enable container logs
   - Monitor for failed auth attempts

---

## 🐛 Troubleshooting

### Image Won't Build

```bash
# Check Docker version
docker --version

# Try with no cache
docker build --no-cache -f Dockerfile -t proxy:socks5 .

# Check disk space
df -h
```

### Container Won't Start

```bash
# Check logs
docker logs container-name

# Check environment variables
docker inspect container-name | grep -A 20 Env

# Try running interactively
docker run -it --rm proxy:socks5 /bin/bash
```

### Can't Connect to Proxy

```bash
# Verify container is running
docker ps | grep proxy

# Check port binding
docker port container-name

# Test network connectivity
telnet localhost 1080
nc -zv localhost 1080

# Check auth credentials
# Make sure username/password are correct
```

### WireGuard Issues

```bash
# Check if kernel supports WireGuard
modprobe wireguard && echo "OK" || echo "Not supported"

# Verify capabilities
docker run --rm --cap-add=NET_ADMIN proxy:wireguard wg --version

# Check TUN device
docker run --rm --device=/dev/net/tun proxy:wireguard ls -l /dev/net/tun
```

---

## 📚 Additional Resources

### Client Configuration

- **Browser Setup**: See `docs/browser-setup.md`
- **App Integration**: See `docs/app-integration.md`
- **WireGuard Keys**: See `docs/wireguard-setup.md`

### API Documentation

- **SOCKS5 Protocol**: RFC 1928
- **HTTP Proxy**: RFC 2616 (CONNECT method)
- **WireGuard**: https://www.wireguard.com/

---

## 📄 Files Structure

```
.
├── Dockerfile                 # SOCKS5 proxy image
├── Dockerfile.http           # HTTP proxy image
├── Dockerfile.wireguard      # WireGuard image
├── socks5_proxy.py          # SOCKS5 implementation
├── http_proxy.py            # HTTP proxy implementation
├── wireguard-start.sh       # WireGuard startup script
├── build-all.sh             # Build all images
└── README.md                # This file
```

---

## 🤝 Contributing

To add new proxy types:

1. Create new Python script (e.g., `shadowsocks_proxy.py`)
2. Create Dockerfile (e.g., `Dockerfile.shadowsocks`)
3. Add to `build-all.sh`
4. Update README

---

## 📊 Comparison

| Feature | SOCKS5 | HTTP | WireGuard |
|---------|--------|------|-----------|
| Protocol | SOCKS5 | HTTP/HTTPS | WireGuard |
| Encryption | No* | HTTPS only | Yes |
| Speed | Fast | Fast | Fastest |
| Compatibility | High | Very High | Moderate |
| Setup Difficulty | Easy | Easy | Medium |
| Cloud Support | ✅ Yes | ✅ Yes | ⚠️ Depends |

*SOCKS5 itself doesn't encrypt, but apps using it (like browsers) provide their own encryption (HTTPS/TLS)

---

## 📞 Support

- **Image Issues**: Check container logs
- **Cloud Deployment**: Contact Claw Cloud support
- **Security**: Follow security best practices above

---

**Version**: 1.0.0  
**License**: MIT  
**Platform**: Linux (amd64, arm64)  
**Cloud Ready**: ✅ Yes
