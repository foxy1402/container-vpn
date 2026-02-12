# Claw Cloud Deployment Guide

## Quick Deploy - Copy & Paste Templates

### 🔵 SOCKS5 Proxy Deployment

**Image**: `ghcr.io/yourusername/proxy:socks5`

**Port**: `1080`

**Environment Variables**:
```yaml
SOCKS5_USER: "your-username"
SOCKS5_PASS: "your-secure-password"
```

**Optional Variables**:
```yaml
SOCKS5_PORT: "1080"
SOCKS5_MAX_CONN: "100"
SOCKS5_TIMEOUT: "60"
```

**Test Command**:
```bash
curl -x socks5://your-username:your-password@your-pod.claw.cloud:1080 https://ifconfig.me
```

---

### 🟢 HTTP Proxy Deployment

**Image**: `ghcr.io/yourusername/proxy:http-proxy`

**Port**: `8080`

**Environment Variables**:
```yaml
HTTP_PROXY_USER: "your-username"
HTTP_PROXY_PASS: "your-secure-password"
```

**Optional Variables**:
```yaml
HTTP_PROXY_PORT: "8080"
HTTP_MAX_CONN: "100"
```

**Test Commands**:
```bash
# HTTP
curl -x http://your-username:your-password@your-pod.claw.cloud:8080 http://httpbin.org/ip

# HTTPS
curl -x http://your-username:your-password@your-pod.claw.cloud:8080 https://ifconfig.me
```

---

### 🟡 WireGuard VPN Deployment

**Image**: `ghcr.io/yourusername/proxy:wireguard`

**Special Requirements**:
- ✅ Platform must support `NET_ADMIN` capability
- ✅ Platform must support `/dev/net/tun` device
- ⚠️ **Check Claw Cloud documentation for WireGuard support**

**Environment Variables** (All Required):
```yaml
WG_PRIVATE_KEY: "your-wg-private-key"
WG_PEER_PUBLIC_KEY: "server-public-key"
WG_ENDPOINT: "vpn.server.com:51820"
```

**Optional Variables**:
```yaml
WG_ADDRESS: "10.0.0.2/24"
WG_DNS: "1.1.1.1"
WG_ALLOWED_IPS: "0.0.0.0/0"
WG_KEEPALIVE: "25"
```

**Generate WireGuard Keys**:
```bash
# Install WireGuard tools locally
apt install wireguard-tools

# Generate your private key
wg genkey
# Example output: cOFA+x1fNRNxewYjO0SYCRmJBZPb3F7U9dlqK4hCb0c=

# Generate public key from private
echo "cOFA+x1fNRNxewYjO0SYCRmJBZPb3F7U9dlqK4hCb0c=" | wg pubkey
# Example output: /BYNcFH4BJ5z2rqq5jHDQi7kN6lxJ2K1QWVNT/DhW3I=
```

---

## 📝 Step-by-Step Deployment

### Step 1: Build and Push Images

```bash
# 1. Clone this repo
git clone https://github.com/yourusername/proxy-images.git
cd proxy-images

# 2. Login to GitHub Container Registry
echo "YOUR_GITHUB_TOKEN" | docker login ghcr.io -u yourusername --password-stdin

# 3. Build all images
./build-all.sh

# 4. Tag for your namespace
docker tag proxy:socks5 ghcr.io/yourusername/proxy:socks5
docker tag proxy:http-proxy ghcr.io/yourusername/proxy:http-proxy
docker tag proxy:wireguard ghcr.io/yourusername/proxy:wireguard

# 5. Push to registry
docker push ghcr.io/yourusername/proxy:socks5
docker push ghcr.io/yourusername/proxy:http-proxy
docker push ghcr.io/yourusername/proxy:wireguard
```

### Step 2: Deploy on Claw Cloud

#### Option A: Web Interface

1. **Login** to Claw Cloud
2. **Create New Pod/App**
3. **Image**: Paste `ghcr.io/yourusername/proxy:socks5`
4. **Port**: Enter `1080`
5. **Environment**: Add variables:
   ```
   SOCKS5_USER=myuser
   SOCKS5_PASS=mypassword
   ```
6. **Deploy** and wait for pod to start

#### Option B: CLI (if Claw supports)

```yaml
# claw-deploy.yaml
apiVersion: v1
kind: Pod
metadata:
  name: socks5-proxy
spec:
  containers:
  - name: proxy
    image: ghcr.io/yourusername/proxy:socks5
    ports:
    - containerPort: 1080
    env:
    - name: SOCKS5_USER
      value: "myuser"
    - name: SOCKS5_PASS
      value: "mypassword"
```

Deploy:
```bash
claw deploy claw-deploy.yaml
```

### Step 3: Test Your Deployment

```bash
# Get your pod URL from Claw Cloud (example: abc123.claw.cloud)

# Test SOCKS5
curl -x socks5://myuser:mypassword@abc123.claw.cloud:1080 https://ifconfig.me

# Test HTTP
curl -x http://myuser:mypassword@abc123.claw.cloud:8080 https://ifconfig.me
```

---

## 🔐 Security Configuration

### Generate Strong Passwords

```bash
# Linux/Mac
openssl rand -base64 32

# Or
head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32
```

### Use Secrets (Recommended)

If Claw Cloud supports secrets:

```yaml
# Don't put passwords in plain text
env:
  - name: SOCKS5_USER
    valueFrom:
      secretKeyRef:
        name: proxy-credentials
        key: username
  - name: SOCKS5_PASS
    valueFrom:
      secretKeyRef:
        name: proxy-credentials
        key: password
```

---

## 🎯 Use Cases

### Use Case 1: Personal SOCKS5 Proxy

**Why**: Secure browsing, bypass restrictions

**Deploy**: SOCKS5 proxy `:socks5`

**Configure Browser**: Firefox → Settings → Network → SOCKS5

### Use Case 2: HTTP API Proxy

**Why**: Proxy HTTP requests from scripts/apps

**Deploy**: HTTP proxy `:http-proxy`

**Use in Code**:
```python
import requests

proxies = {
    'http': 'http://user:pass@your-pod.claw.cloud:8080',
    'https': 'http://user:pass@your-pod.claw.cloud:8080'
}

response = requests.get('https://api.example.com', proxies=proxies)
```

### Use Case 3: VPN Tunnel

**Why**: Encrypt all traffic, hide IP

**Deploy**: WireGuard `:wireguard` (if supported)

**Requirements**: WireGuard server already set up

---

## 📊 Resource Requirements

### Minimum Requirements (per pod)

| Service | CPU | RAM | Disk |
|---------|-----|-----|------|
| SOCKS5 | 0.1 core | 128 MB | 100 MB |
| HTTP | 0.1 core | 128 MB | 80 MB |
| WireGuard | 0.2 core | 64 MB | 90 MB |

### Recommended for Production

| Service | CPU | RAM | Disk |
|---------|-----|-----|------|
| SOCKS5 | 0.5 core | 512 MB | 200 MB |
| HTTP | 0.5 core | 512 MB | 200 MB |
| WireGuard | 0.5 core | 256 MB | 200 MB |

---

## 🔧 Customization

### Increase Connection Limits

```yaml
# For SOCKS5
SOCKS5_MAX_CONN: "200"

# For HTTP
HTTP_MAX_CONN: "200"
```

### Change Ports

```yaml
# SOCKS5 on port 2080
SOCKS5_PORT: "2080"

# HTTP on port 9090
HTTP_PROXY_PORT: "9090"
```

### Adjust Timeouts

```yaml
# SOCKS5 - longer timeout for slow connections
SOCKS5_TIMEOUT: "120"
SOCKS5_IDLE_TIMEOUT: "600"
```

---

## 🐛 Troubleshooting

### Pod Won't Start

**Check logs** in Claw Cloud console:
```
Error: Environment variable SOCKS5_USER not set
```
→ Solution: Add missing environment variables

### Can't Connect to Proxy

**Check**:
1. Pod is running (status: Running)
2. Port is exposed (1080 or 8080)
3. Environment variables are set correctly
4. Credentials are correct

**Test connectivity**:
```bash
# Test if port is open
nc -zv your-pod.claw.cloud 1080

# Test with telnet
telnet your-pod.claw.cloud 1080
```

### Authentication Fails

**Verify credentials**:
```bash
# Check what you set in Claw Cloud
# Then test with exact same values
curl -x socks5://EXACT_USER:EXACT_PASS@your-pod:1080 https://ifconfig.me
```

### WireGuard Won't Work

**Check**:
1. Platform supports NET_ADMIN capability
2. /dev/net/tun is available
3. All required env vars are set
4. Keys are correct (no extra spaces/newlines)

**Contact** Claw Cloud support to verify WireGuard support

---

## 📈 Monitoring

### Check Health

Most cloud platforms show container health from Docker health checks.

**Health check runs**:
- Every 30 seconds
- 3 retries before marking unhealthy
- Auto-restart if unhealthy

### View Logs

In Claw Cloud console:
1. Select your pod
2. Click "Logs" tab
3. View real-time logs

**Look for**:
```
✓ SOCKS5 Proxy started successfully on 0.0.0.0:1080
Connection from ('1.2.3.4', 12345)
```

---

## 🔄 Updates

### Update Images

```bash
# 1. Pull latest code
git pull

# 2. Rebuild images
./build-all.sh

# 3. Push new versions
docker push ghcr.io/yourusername/proxy:socks5

# 4. Restart pod in Claw Cloud
# (or use rolling update if supported)
```

### Zero-Downtime Updates

If Claw supports:
1. Deploy new version alongside old
2. Switch traffic to new version
3. Remove old version

---

## 💡 Tips & Tricks

### 1. Use Different Images for Different Environments

```bash
# Tag for staging
docker tag proxy:socks5 ghcr.io/yourusername/proxy:socks5-staging

# Tag for production
docker tag proxy:socks5 ghcr.io/yourusername/proxy:socks5-production
```

### 2. Monitor Resource Usage

Check Claw Cloud metrics:
- CPU usage (should be <50%)
- RAM usage (should be <70%)
- Network traffic

### 3. Backup Configurations

Save your environment variables:
```yaml
# proxy-config-backup.yaml
socks5:
  user: myuser
  pass: mypassword
  max_conn: 100

http:
  user: myuser
  pass: mypassword
```

---

## 📞 Support

**Image Issues**: Check logs and GitHub issues  
**Claw Cloud Issues**: Contact Claw support  
**Security Concerns**: Update credentials immediately

---

## ✅ Deployment Checklist

Before deploying to production:

- [ ] Changed default username/password
- [ ] Used strong password (20+ chars)
- [ ] Tested locally with docker-compose
- [ ] Pushed images to registry
- [ ] Set appropriate resource limits
- [ ] Configured health checks
- [ ] Tested connectivity
- [ ] Documented credentials securely
- [ ] Set up monitoring/alerts
- [ ] Planned backup strategy

---

**Ready to deploy?** Follow Step 1 above! 🚀
