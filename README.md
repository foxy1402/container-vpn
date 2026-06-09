# container-vpn

Cloud-ready container images for five independent services:

- SOCKS5 proxy (`:socks5`)
- HTTP/HTTPS proxy (`:http-proxy`)
- GOST multi-protocol proxy (`:gost`)
- Cloud Metrics Gateway — WebSocket-based service (`:metrics-gateway`)
- TLSGost SOCKS5+TLS / HTTP CONNECT+TLS proxy (`:tlsgost`)

Each service is deployed separately (one container per service).

## Published images (copy/paste)

- `ghcr.io/foxy1402/container-vpn:socks5`
- `ghcr.io/foxy1402/container-vpn:http-proxy`
- `ghcr.io/foxy1402/container-vpn:gost`
- `ghcr.io/foxy1402/container-vpn:metrics-gateway`
- `ghcr.io/foxy1402/container-vpn:tlsgost`

## Images and ports

| Image | Purpose | Port |
|---|---|---|
| `ghcr.io/foxy1402/container-vpn:socks5` | SOCKS5 with username/password auth | `1080/tcp` |
| `ghcr.io/foxy1402/container-vpn:http-proxy` | HTTP proxy + HTTPS CONNECT tunnel | `8080/tcp` |
| `ghcr.io/foxy1402/container-vpn:gost` | Multi-protocol on one port (SOCKS5 + HTTP CONNECT + optional Shadowsocks) | `8080/tcp` |
| `ghcr.io/foxy1402/container-vpn:metrics-gateway` | WebSocket-based service — for platforms that only expose HTTP/HTTPS | `8080/tcp` |
| `ghcr.io/foxy1402/container-vpn:tlsgost` | SOCKS5+TLS and HTTP CONNECT+TLS on one port with auto-generated or custom TLS cert | `8443/tcp` |

## Build

Build all images:

```bash
./build-all.sh
```

Or build one:

```bash
docker build -f Dockerfile -t proxy:socks5 .
docker build -f Dockerfile.http -t proxy:http-proxy .
docker build -f Dockerfile.gost -t proxy:gost .
docker build -f Dockerfile.wsgost -t proxy:metrics-gateway .
docker build -f Dockerfile.tlsgost -t proxy:tlsgost .
```

## Portainer deploy (required fields only)

Use `Containers` -> `Add container` in Portainer. Ignore optional fields unless you need customization.

### SOCKS5 (`:socks5`)

- Name: `socks5`
- Image: `ghcr.io/foxy1402/container-vpn:socks5`
- Publish a new network port: host `1080` -> container `1080` (`tcp`)
- Environment variables:
  - `SOCKS5_USER=your-username`
  - `SOCKS5_PASS=your-strong-password`
- Deploy the container

### HTTP proxy (`:http-proxy`)

- Name: `http-proxy`
- Image: `ghcr.io/foxy1402/container-vpn:http-proxy`
- Publish a new network port: host `8080` -> container `8080` (`tcp`)
- Environment variables:
  - `HTTP_PROXY_USER=your-username`
  - `HTTP_PROXY_PASS=your-strong-password`
- Deploy the container

### GOST (`:gost`)

- Name: `gost-proxy`
- Image: `ghcr.io/foxy1402/container-vpn:gost`
- Publish a new network port: host `8080` -> container `8080` (`tcp`)
- Environment variables:
  - `GOST_USER=your-username`
  - `GOST_PASS=your-strong-password`
- Deploy the container

### Metrics Gateway (`:metrics-gateway`)

- Name: `metrics-gateway`
- Image: `ghcr.io/foxy1402/container-vpn:metrics-gateway`
- Publish a new network port: host `8080` -> container `8080` (`tcp`)
- Environment variables:
  - `SERVICE_MODE=standard` (or `enhanced`)
  - `SERVICE_TOKEN=your-uuid` (required when `SERVICE_MODE=standard`)
  - `SERVICE_CREDENTIAL=your-password` (required when `SERVICE_MODE=enhanced`)
  - `SERVICE_ENDPOINT=/your-secret-random-path`
- Deploy the container

### TLSGost (`:tlsgost`)

- Name: `tlsgost-proxy`
- Image: `ghcr.io/foxy1402/container-vpn:tlsgost`
- Publish a new network port: host `8443` -> container `8443` (`tcp`)
- Environment variables:
  - `TLSGOST_USER=your-username`
  - `TLSGOST_PASS=your-strong-password`
- Deploy the container

## 1) SOCKS5 proxy

Required env:

- `SOCKS5_USER`
- `SOCKS5_PASS`

Recommended env block (copy/paste):

```yaml
SOCKS5_USER: "your-username"
SOCKS5_PASS: "your-strong-password"
SOCKS5_FORCE_IPV4: "true"
SOCKS5_LOG_LEVEL: "INFO"
```

Optional env:

- `SOCKS5_HOST` (default `0.0.0.0`)
- `SOCKS5_PORT` (default `1080`)
- `SOCKS5_MAX_CONN` (default `200`)
- `SOCKS5_TIMEOUT` (default `15`)
- `SOCKS5_IDLE_TIMEOUT` (default `300`)
- `SOCKS5_AUTH_FAIL_LIMIT` (default `5`)
- `SOCKS5_AUTH_FAIL_WINDOW` (default `60`)
- `SOCKS5_FORCE_IPV4` (default `true`, recommended for IPv4-only cloud egress)
- `SOCKS5_ALLOW_NOAUTH` (default `false`, only enable if your client app cannot use user/pass)
- `SOCKS5_LOG_LEVEL` (default `INFO`, use `DEBUG` for troubleshooting)

Run:

```bash
docker run -d \
  --name socks5 \
  -p 1080:1080 \
  -e SOCKS5_USER=myuser \
  -e SOCKS5_PASS='strong-password' \
  ghcr.io/foxy1402/container-vpn:socks5
```

Test:

```bash
curl -x socks5://myuser:strong-password@127.0.0.1:1080 https://ifconfig.me
```

## 2) HTTP/HTTPS proxy

Required env:

- `HTTP_PROXY_USER`
- `HTTP_PROXY_PASS`

Recommended env block (copy/paste):

```yaml
HTTP_PROXY_USER: "your-username"
HTTP_PROXY_PASS: "your-strong-password"
HTTP_PROXY_FORCE_IPV4: "true"
```

Optional env:

- `HTTP_PROXY_HOST` (default `0.0.0.0`)
- `HTTP_PROXY_PORT` (default `8080`)
- `HTTP_MAX_CONN` (default `200`)
- `HTTP_PROXY_TIMEOUT` (default `30`)
- `HTTP_PROXY_IDLE_TIMEOUT` (default `300`)
- `HTTP_AUTH_FAIL_LIMIT` (default `5`)
- `HTTP_AUTH_FAIL_WINDOW` (default `60`)
- `HTTP_PROXY_FORCE_IPV4` (default `true`, recommended for IPv4-only cloud egress)

Run:

```bash
docker run -d \
  --name http-proxy \
  -p 8080:8080 \
  -e HTTP_PROXY_USER=myuser \
  -e HTTP_PROXY_PASS='strong-password' \
  ghcr.io/foxy1402/container-vpn:http-proxy
```

Test:

```bash
curl -x http://myuser:strong-password@127.0.0.1:8080 https://ifconfig.me
```

## 3) GOST multi-protocol proxy

This image supports SOCKS5 + HTTP CONNECT on one port, and optional Shadowsocks on the same port.

Authentication/credentials are configured via environment variables.

Required env:

- `GOST_USER`
- `GOST_PASS`

Recommended env block (copy/paste):

```yaml
GOST_USER: "your-username"
GOST_PASS: "your-strong-password"
GOST_HANDSHAKE_TIMEOUT: "45"
GOST_TIMEOUT: "30"
GOST_FORCE_IPV4: "true"
```

Optional env:

- `GOST_HOST` (default `0.0.0.0`)
- `GOST_PORT` (default `8080`)
- `GOST_SS_KEY` (optional, enables Shadowsocks when set; this is your Shadowsocks password)
- `GOST_SS_CIPHER` (default `aes-256-gcm`)
- `GOST_MAX_CONN` (default `200`)
- `GOST_HANDSHAKE_TIMEOUT` (default `30`, recommended `45` for mobile app compatibility)
- `GOST_TIMEOUT` (default `15`)
- `GOST_IDLE_TIMEOUT` (default `300`)
- `GOST_AUTH_FAIL_LIMIT` (default `5`)
- `GOST_AUTH_FAIL_WINDOW` (default `60`)
- `GOST_ALLOW_NOAUTH` (default `false`)
- `GOST_FORCE_IPV4` (default `true`)

Run:

```bash
docker run -d \
  --name gost-proxy \
  -p 8080:8080 \
  -e GOST_USER=myuser \
  -e GOST_PASS='strong-password' \
  -e GOST_SS_KEY='your-shadowsocks-password' \
  ghcr.io/foxy1402/container-vpn:gost
```

Test:

```bash
# SOCKS5
curl -x socks5h://myuser:strong-password@127.0.0.1:8080 https://ifconfig.me

# HTTP CONNECT
curl -x http://myuser:strong-password@127.0.0.1:8080 https://ifconfig.me
```

Mobile app note:

- Some apps (for example Super Proxy on Android) use external connectivity-check URLs.
- If those check endpoints are blocked/slow in your cloud region, the app can show false timeout/failure even when proxy is working.
- If your app supports it, disable connectivity check (or change its check URL) when using this proxy.

Shadowsocks Android compatibility note:

- SagerNet works with this setup, but set client routing/domain strategy to prefer IPv4 (or disable IPv6) when server uses `GOST_FORCE_IPV4=true`.
- `shadowsocks-android` `v5.3.4` is reported working with this server.
- `shadowsocks-android` `v5.3.5-nightly` is reported not working in this setup.

## 4) Metrics Gateway — VLESS / Trojan over WebSocket

This image runs **VLESS** or **Trojan** over WebSocket, designed for PaaS platforms that only expose HTTP/HTTPS (port 443) — Railway, Render, Fly.io, Koyeb, Zeabur, Northflank, etc.

The platform terminates TLS; the container serves plain WebSocket internally.

```
Client app (VLESS/Trojan over wss://) ──▶ Platform TLS (443) ──▶ WebSocket (8080) in container
```

**Why this works:** Your traffic looks like normal HTTPS WebSocket connections to any observer. No raw TCP ports are exposed.

---

### Protocol modes

| Mode | Protocol | Use case |
|---|---|---|
| `SERVICE_MODE=standard` | **VLESS** | Recommended. Lightweight, no double encryption |
| `SERVICE_MODE=enhanced` | **Trojan** | Mimics normal HTTPS traffic patterns |

---

### Quick start

#### 1. Generate a UUID

For VLESS (standard mode), you need a UUID. Generate one:

```bash
# Linux / macOS
uuidgen

# Or use an online generator
# https://www.uuidgenerator.net/
```

Example output: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`

#### 2. Deploy the container

**Local test:**

```bash
docker run -d \
  --name metrics-gateway \
  -p 8080:8080 \
  -e SERVICE_MODE=standard \
  -e SERVICE_TOKEN='a1b2c3d4-e5f6-7890-abcd-ef1234567890' \
  -e SERVICE_ENDPOINT='/mysecret8765' \
  ghcr.io/foxy1402/container-vpn:metrics-gateway
```

**PaaS deployment (Railway / Render / Fly.io / Koyeb):**

1. Create a new service and set the image:
   ```
   ghcr.io/foxy1402/container-vpn:metrics-gateway
   ```
2. Set environment variables:
   ```yaml
   SERVICE_MODE: "standard"
   SERVICE_TOKEN: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
   SERVICE_ENDPOINT: "/mysecret8765"
   ```
3. Deploy. The platform automatically injects `PORT` and routes `https://yourapp.platform.com` → container.

**Verify it's running:**

```bash
docker exec metrics-gateway /app/service-healthcheck.sh
```

---

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SERVICE_MODE` | `standard` | `standard` (VLESS) or `enhanced` (Trojan) |
| `SERVICE_TOKEN` | — | **Required for VLESS.** Your UUID |
| `SERVICE_CREDENTIAL` | — | **Required for Trojan.** Your password |
| `SERVICE_ENDPOINT` | `/api/v1/metrics` | WebSocket path. **Use a random string** (e.g. `/x9KmQr8765`) |
| `SERVICE_PORT` | `8080` | Internal port. PaaS injects `PORT` automatically |
| `SERVICE_HOST` | `0.0.0.0` | Bind address |
| `LOG_LEVEL` | `warning` | `debug`, `info`, `warning`, `error`, `none` |

---

### Client setup (v2rayNG / Shadowrocket / v2raytun)

After deploying, configure your client app with these settings:

#### VLESS mode (`SERVICE_MODE=standard`)

**v2rayNG (Android):**
1. Tap **+** → **Type: VLESS**
2. Fill in:
   - **Address:** `yourapp.railway.app` (your actual domain)
   - **Port:** `443`
   - **UUID:** `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
   - **Flow:** leave empty
   - **Encryption:** `none`
3. Tap **Transport** → **Type: ws**
   - **Host:** `yourapp.railway.app` (same as Address)
   - **Path:** `/mysecret8765` (your SERVICE_ENDPOINT)
4. Tap **TLS** → **Security: tls**
   - **SNI:** `yourapp.railway.app` (same as Address)
   - **Fingerprint:** `chrome` (or leave default)
5. Save and connect

**Shadowrocket (iOS):**
1. Tap **+** → **Type: VLESS**
2. **Address:** `yourapp.railway.app`
3. **Port:** `443`
4. **UUID:** `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
5. **Flow:** leave empty
6. **Method:** `none`
7. **TLS** → enable → **Peer Name:** `yourapp.railway.app`
8. **Network** → **ws**
   - **WebSocket Host:** `yourapp.railway.app`
   - **WebSocket Path:** `/mysecret8765`
9. Save and connect

#### Trojan mode (`SERVICE_MODE=enhanced`)

Same steps as above, but:
- **Type:** Trojan
- **Password:** your `SERVICE_CREDENTIAL` value (instead of UUID)
- Everything else is identical

---

### DNS leak prevention (important!)

By default, clients may resolve DNS locally instead of through the tunnel, leaking your DNS queries.

**Fix for v2raytun / sing-box:**

1. Open app → **Settings (⚙)** → **DNS**
2. **Remote DNS:** `https://1.1.1.1/dns-query` (or Cloudflare/Google DoH)
3. **Domestic DNS:** `https://1.1.1.1/dns-query`
4. **Domain Strategy:** `UseIPv4` or `IPIfNonMatch`
5. Save and reconnect

**Fix for v2rayNG:**

1. Open app → **Settings** → **DNS**
2. Enable **Use custom DNS**
3. **Remote DNS:** `https://1.1.1.1/dns-query`
4. **Domain Strategy:** `UseIPv4`
5. Save and reconnect

---

### Built-in DNS resolver

The service includes a DNS-over-HTTPS (DoH) resolver at `/dns-query` (configurable via `RESOLVER_PATH`).

**Use it as your client's DNS server:**

```
https://yourapp.railway.app/dns-query
```

Set this as the **Remote DNS** in your client app settings to route all DNS through the tunnel.

---

### Connection templates (for clipboard import)

If your client app supports clipboard import (v2rayNG, Shadowrocket, v2raytun), you can generate a share link and paste it directly.

#### VLESS template

Replace the placeholders with your actual values:

```
vless://YOUR_UUID@yourapp.railway.app:443?encryption=none&security=tls&sni=yourapp.railway.app&type=ws&host=yourapp.railway.app&path=/mysecret8765#metrics
```

**Example:**
```
vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@myapp.railway.app:443?encryption=none&security=tls&sni=myapp.railway.app&type=ws&host=myapp.railway.app&path=/mysecret8765#metrics
```

#### Trojan template

Replace the placeholders with your actual values:

```
trojan://YOUR_PASSWORD@yourapp.railway.app:443?security=tls&sni=yourapp.railway.app&type=ws&host=yourapp.railway.app&path=/mysecret8765#metrics
```

**Example:**
```
trojan://mystrongpassword123@myapp.railway.app:443?security=tls&sni=myapp.railway.app&type=ws&host=myapp.railway.app&path=/mysecret8765#metrics
```

**How to use:**
1. Copy the template above
2. Replace `YOUR_UUID` or `YOUR_PASSWORD` with your actual value
3. Replace `yourapp.railway.app` with your actual domain (appears 3 times)
4. Replace `/mysecret8765` with your `SERVICE_ENDPOINT` value
5. Copy the final link to your clipboard
6. Open your client app and tap **Import from clipboard** (or similar)

---

### QR code generation (for apps that require QR scan)

If your client app (like v2raytun on Android) only accepts QR code imports, use one of these free online tools:

#### Option 1: QR Server (recommended)
1. Go to: https://goqr.me/
2. Paste your complete VLESS or Trojan link (from the templates above)
3. Download the QR code image
4. Open your client app and scan the QR code

#### Option 2: QRCode Monkey
1. Go to: https://www.qrcode-monkey.com/
2. Paste your link in the **Text** field
3. Click **Create QR Code**
4. Download and scan with your app

#### Option 3: Command line (Linux/macOS)
```bash
# Install qrencode (if not already installed)
sudo apt install qrencode  # Ubuntu/Debian
brew install qrencode      # macOS

# Generate QR code
echo "vless://YOUR_UUID@yourapp.railway.app:443?encryption=none&security=tls&sni=yourapp.railway.app&type=ws&host=yourapp.railway.app&path=/mysecret8765#metrics" | qrencode -o metrics-qr.png

# Open the QR code image
xdg-open metrics-qr.png  # Linux
open metrics-qr.png      # macOS
```

#### Option 4: Python script
```python
import qrcode

# Your connection link
link = "vless://YOUR_UUID@yourapp.railway.app:443?encryption=none&security=tls&sni=yourapp.railway.app&type=ws&host=yourapp.railway.app&path=/mysecret8765#metrics"

# Generate QR code
qr = qrcode.QRCode(version=1, box_size=10, border=5)
qr.add_data(link)
qr.make(fit=True)
img = qr.make_image(fill_color="black", back_color="white")
img.save("metrics-qr.png")
print("QR code saved as metrics-qr.png")
```

Install required package: `pip install qrcode[pil]`

---

### Troubleshooting

**"Connection failed" or timeout:**
- Verify `SERVICE_ENDPOINT` matches your client's **Path** setting exactly (including the leading `/`)
- Check that **Host** and **SNI** match your actual domain (not `localhost` or IP)
- Ensure TLS is enabled on port 443

**"DNS_PROBE_POSSIBLE" or can't load websites:**
- This is a DNS leak issue (see above)
- Set **Domain Strategy** to `UseIPv4` in your client
- Use a DoH server like `https://1.1.1.1/dns-query` as Remote DNS

**Container won't start:**
- Check logs: `docker logs metrics-gateway`
- Ensure `SERVICE_TOKEN` (for VLESS) or `SERVICE_CREDENTIAL` (for Trojan) is set
- Verify `SERVICE_ENDPOINT` starts with `/`

---

### Security recommendations

1. **Use a random endpoint path** — Don't use `/ws` or `/api`. Use something like `/x9KmQr8765v2`
2. **Rotate UUIDs periodically** — Generate new UUIDs every few months
3. **Use strong passwords** for Trojan mode (16+ characters, mixed case, numbers, symbols)
4. **Enable DNS leak protection** in your client (see above)

---

### Share link format

For quick import, the service generates share links in this format:

**VLESS:**
```
vless://UUID@domain:443?type=ws&security=tls&path=%2Fmysecret8765&host=domain&sni=domain#metrics
```

**Trojan:**
```
trojan://password@domain:443?type=ws&security=tls&path=%2Fmysecret8765&host=domain&sni=domain#metrics
```

Most client apps (v2rayNG, Shadowrocket, v2raytun) can import these directly via QR code or clipboard.

## 5) TLSGost — SOCKS5+TLS / HTTP CONNECT+TLS proxy

This image wraps SOCKS5 and HTTP CONNECT inside TLS on a single port. Clients connect over TLS and the proxy auto-detects whether the inner protocol is SOCKS5 or HTTP CONNECT. If no TLS certificate is provided, a self-signed ECDSA P-256 certificate is generated at startup and automatically renewed 30 days before expiry.

```
Client (SOCKS5 or HTTP CONNECT over TLS) ──▶ TLSGost (TLS termination + auto-detect) ──▶ Internet
```

Required env:

- `TLSGOST_USER`
- `TLSGOST_PASS`

Recommended env block (copy/paste):

```yaml
TLSGOST_USER: "your-username"
TLSGOST_PASS: "your-strong-password"
TLSGOST_FORCE_IPV4: "true"
```

Optional env:

- `TLSGOST_HOST` (default `0.0.0.0`)
- `TLSGOST_PORT` (default `8443`)
- `TLSGOST_TLS_CERT` (optional, path to PEM certificate file; auto-generates self-signed if empty)
- `TLSGOST_TLS_KEY` (optional, path to PEM private key file; required with `TLSGOST_TLS_CERT`)
- `TLSGOST_TLS_MIN_VERSION` (default `1.2`, set to `1.3` to require TLS 1.3)
- `TLSGOST_SNI` (optional, rejects TLS connections where client SNI does not match this value)
- `TLSGOST_MAX_CONN` (default `200`)
- `TLSGOST_HANDSHAKE_TIMEOUT` (default `30`)
- `TLSGOST_TIMEOUT` (default `15`)
- `TLSGOST_IDLE_TIMEOUT` (default `300`)
- `TLSGOST_AUTH_FAIL_LIMIT` (default `5`)
- `TLSGOST_AUTH_FAIL_WINDOW` (default `60`)
- `TLSGOST_ALLOW_NOAUTH` (default `false`)
- `TLSGOST_FORCE_IPV4` (default `true`, recommended for IPv4-only cloud egress)



## docker compose

Local test for SOCKS5 + HTTP:

```bash
docker compose up -d socks5 http-proxy
```

## Minimal OS compatibility

These images target Debian 13 slim style environments. Runtime dependencies are kept small:

- Proxy images (socks5, http-proxy): Python 3 + stdlib only
- GOST image: static Go binary + `ca-certificates`
- Metrics Gateway image: service binary + `ca-certificates`
- TLSGost image: static Go binary + `ca-certificates`

## CI build

GitHub workflow file: `.github/workflows/build.yml`

- Builds all images (`socks5`, `http-proxy`, `gost`, `metrics-gateway`, `tlsgost`) for `linux/amd64` and `linux/arm64`
- Pushes to GHCR on non-PR events
- Runs service-specific smoke checks

## Security notes

- Do not deploy with weak credentials.
- Store proxy credentials in platform secrets.
- Restrict inbound access with firewall/security groups.
- For Metrics Gateway, set `SERVICE_ENDPOINT` to a random secret path to avoid unauthenticated WS probing.
- For TLSGost, self-signed certs auto-renew and are fine for personal use. Provide your own TLS certificate for production or public-facing deployments.

## Deployment references

- Quick start: `START-HERE.md`
- Claw deployment details: `CLAW-DEPLOYMENT.md`

