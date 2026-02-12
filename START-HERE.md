# 🚀 START HERE - Cloud Proxy Images for Claw Cloud

**Production-ready proxy images** designed for cloud deployment platforms where **one pod = one service**.

---

## 📦 What You Get

Three separate Docker images, each with a unique tag:

| Image Tag | Service | Port | Size | Use Case |
|-----------|---------|------|------|----------|
| `:socks5` | SOCKS5 Proxy | 1080 | ~80MB | General proxying, browser config |
| `:http-proxy` | HTTP/HTTPS Proxy | 8080 | ~60MB | API proxying, HTTP traffic |
| `:wireguard` | WireGuard VPN | - | ~70MB | Full VPN tunnel (requires NET_ADMIN) |

---

## ⚡ Quick Start (3 Steps)

### Step 1: Build Images

```bash
# Clone this repository
git clone https://github.com/yourusername/cloud-proxy.git
cd cloud-proxy

# Build all images at once
./build-all.sh
```

This creates:
- `proxy:socks5`
- `proxy:http-proxy`
- `proxy:wireguard`

### Step 2: Push to Registry

```bash
# Login to GitHub Container Registry
echo "YOUR_GITHUB_TOKEN" | docker login ghcr.io -u yourusername --password-stdin

# Tag for your namespace
docker tag proxy:socks5 ghcr.io/yourusername/proxy:socks5
docker tag proxy:http-proxy ghcr.io/yourusername/proxy:http-proxy
docker tag proxy:wireguard ghcr.io/yourusername/proxy:wireguard

# Push
docker push ghcr.io/yourusername/proxy:socks5
docker push ghcr.io/yourusername/proxy:http-proxy
docker push ghcr.io/yourusername/proxy:wireguard
```

### Step 3: Deploy on Claw Cloud

See **[CLAW-DEPLOYMENT.md](CLAW-DEPLOYMENT.md)** for detailed deployment instructions with copy-paste templates!

---

## 🎯 Deployment Templates

### SOCKS5 Proxy

**Image**: `ghcr.io/yourusername/proxy:socks5`  
**Port**: `1080`  
**Environment**:
```yaml
SOCKS5_USER: "your-username"
SOCKS5_PASS: "your-secure-password"
```

### HTTP Proxy

**Image**: `ghcr.io/yourusername/proxy:http-proxy`  
**Port**: `8080`  
**Environment**:
```yaml
HTTP_PROXY_USER: "your-username"
HTTP_PROXY_PASS: "your-secure-password"
```

### WireGuard VPN

**Image**: `ghcr.io/yourusername/proxy:wireguard`  
**Requirements**: NET_ADMIN capability, /dev/net/tun device  
**Environment**:
```yaml
WG_PRIVATE_KEY: "your-private-key"
WG_PEER_PUBLIC_KEY: "server-public-key"
WG_ENDPOINT: "vpn.server.com:51820"
```

---

## 📚 Documentation

- **[README.md](README.md)** - Complete documentation, all features
- **[CLAW-DEPLOYMENT.md](CLAW-DEPLOYMENT.md)** - Claw Cloud deployment guide with templates
- **[docker-compose.yml](docker-compose.yml)** - Local testing setup
- **[.github-workflows-build.yml](.github-workflows-build.yml)** - GitHub Actions for automated builds

---

## 🧪 Test Locally

```bash
# Test with docker-compose
docker-compose up -d

# Test SOCKS5
curl -x socks5://testuser:testpass@localhost:1080 https://ifconfig.me

# Test HTTP
curl -x http://testuser:testpass@localhost:8080 https://ifconfig.me

# Clean up
docker-compose down
```

---

## 🔧 Files Overview

```
.
├── Dockerfile                    # SOCKS5 proxy
├── Dockerfile.http              # HTTP proxy
├── Dockerfile.wireguard         # WireGuard VPN
├── socks5_proxy.py             # SOCKS5 implementation
├── http_proxy.py               # HTTP proxy implementation
├── wireguard-start.sh          # WireGuard startup
├── build-all.sh                # Build script
├── docker-compose.yml          # Local testing
├── README.md                   # Full documentation
├── CLAW-DEPLOYMENT.md          # Deployment guide
└── .github-workflows-build.yml # CI/CD automation
```

---

## ✨ Features

✅ **Cloud-Ready**: Each image is standalone, no dependencies  
✅ **Self-Healing**: Built-in health checks and auto-restart  
✅ **Minimal Size**: Debian 13 slim base (~60-80MB per image)  
✅ **Secure**: Non-root user, authentication required  
✅ **Production-Tested**: Includes proper logging and error handling  
✅ **Multi-Platform**: Supports amd64 and arm64  

---

## 🔐 Security

**Important**: Change default credentials!

```bash
# Generate strong password
openssl rand -base64 32

# Use in deployment
SOCKS5_USER=myuser
SOCKS5_PASS=generated-strong-password-here
```

---

## 📞 Need Help?

1. **Local Testing Issues**: Run `docker-compose up` and check logs
2. **Build Issues**: Check `build-all.sh` output for errors
3. **Deployment Issues**: See [CLAW-DEPLOYMENT.md](CLAW-DEPLOYMENT.md) troubleshooting section
4. **WireGuard Issues**: Verify platform supports NET_ADMIN

---

## 🎓 Next Steps

1. ✅ Build images with `./build-all.sh`
2. ✅ Test locally with `docker-compose up`
3. ✅ Push to your container registry
4. ✅ Deploy on Claw Cloud using [CLAW-DEPLOYMENT.md](CLAW-DEPLOYMENT.md)

---

**Version**: 1.0.0  
**Platform**: Linux (amd64, arm64)  
**Cloud Compatible**: ✅ Claw Cloud, Kubernetes, Docker, etc.
