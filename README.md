# container-vpn

Cloud-ready container images for four independent services:

- SOCKS5 proxy (`:socks5`)
- HTTP/HTTPS proxy (`:http-proxy`)
- GOST multi-protocol proxy (`:gost`)
- WSGOST WebSocket-to-GOST bridge (`:wsgost`)

Each service is deployed separately (one container per service).

## Published images (copy/paste)

- `ghcr.io/foxy1402/container-vpn:socks5`
- `ghcr.io/foxy1402/container-vpn:http-proxy`
- `ghcr.io/foxy1402/container-vpn:gost`
- `ghcr.io/foxy1402/container-vpn:wsgost`

## Images and ports

| Image | Purpose | Port |
|---|---|---|
| `ghcr.io/foxy1402/container-vpn:socks5` | SOCKS5 with username/password auth | `1080/tcp` |
| `ghcr.io/foxy1402/container-vpn:http-proxy` | HTTP proxy + HTTPS CONNECT tunnel | `8080/tcp` |
| `ghcr.io/foxy1402/container-vpn:gost` | Multi-protocol on one port (SOCKS5 + HTTP CONNECT + optional Shadowsocks) | `8080/tcp` |
| `ghcr.io/foxy1402/container-vpn:wsgost` | GOST proxy tunnelled over WebSocket — for platforms that only expose HTTP/HTTPS | `8080/tcp` |

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
docker build -f Dockerfile.wsgost -t proxy:wsgost .
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

### WSGOST (`:wsgost`)

- Name: `wsgost-proxy`
- Image: `ghcr.io/foxy1402/container-vpn:wsgost`
- Publish a new network port: host `8080` -> container `8080` (`tcp`)
- Environment variables:
  - `GOST_USER=your-username`
  - `GOST_PASS=your-strong-password`
  - `WS_PATH=/your-secret-random-path`
  - `GOST_SS_KEY=your-shadowsocks-password` (optional — enables SS + QR code)
- Deploy the container
- Open the config portal: `http://yourhost:8080/login?pass=<derived from GOST_PASS>`

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

## 4) WSGOST — WebSocket-to-GOST bridge

Use this image on platforms that only expose **HTTP/HTTPS** (port 443) and do not allow raw TCP/UDP ports — Railway, Render, Fly.io, Koyeb, Zeabur, Northflank, etc.

Inside the container: GOST runs on loopback (`127.0.0.1:18080`, never exposed). The WebSocket bridge listens on the single public port (`8080`) and tunnels every WebSocket connection straight into GOST. The platform terminates TLS, so your client sees `wss://yourapp.platform.com/path`.

```
Client app  ──wss://──▶  Platform TLS edge  ──ws://──▶  wsgost-bridge  ──tcp──▶  gost-proxy
```

---

### Quick local test

```bash
docker run -d \
  --name wsgost \
  -p 8080:8080 \
  -e GOST_USER=myuser \
  -e GOST_PASS='strong-password' \
  -e WS_PATH='/mysecretpath' \
  -e GOST_SS_KEY='your-shadowsocks-password' \
  -e GOST_FORCE_IPV4=true \
  ghcr.io/foxy1402/container-vpn:wsgost
```

Verify it is up:

```bash
curl http://127.0.0.1:8080/health   # → ok
```

---

### Deploy on a PaaS platform (Railway / Render / Fly.io / Koyeb / …)

All platforms follow the same pattern — only the UI differs:

1. Create a new service / app and set the image to:
   ```
   ghcr.io/foxy1402/container-vpn:wsgost
   ```
2. Set environment variables (see table below). The platform automatically injects `PORT`; you do **not** need to set `WS_PORT` manually.
3. Do **not** open or map any custom port. The platform routes `https://yourapp.platform.com` → container port automatically.
4. Deploy. Once healthy, open the config portal (see below) to get ready-made share links.

> **Fly.io** — add `[[services]]` mapping internal port `8080` to external port `443` in `fly.toml`.  
> **Render** — set "Start Command" to `/app/wsgost-start.sh`; the image already has `CMD` set correctly.

---

### Environment variables

#### Required

| Variable | Description |
|---|---|
| `GOST_USER` | Proxy username for SOCKS5 / HTTP authentication |
| `GOST_PASS` | Proxy password — also used to derive the portal password |

#### Recommended

```yaml
GOST_USER: "myuser"
GOST_PASS: "strong-password"
WS_PATH: "/your-secret-random-path"   # change this — keeps unauthenticated bots out
GOST_SS_KEY: "your-shadowsocks-key"   # enables Shadowsocks + QR code on /login
GOST_FORCE_IPV4: "true"
```

#### WebSocket bridge

| Variable | Default | Description |
|---|---|---|
| `WS_PATH` | `/ws` | WebSocket endpoint path. **Set a random string** (e.g. `/xK9mQr`) for security |
| `PORT` / `WS_PORT` | `8080` | Container listen port. Platforms inject `PORT` automatically — leave unset |
| `WS_HOST` | `0.0.0.0` | Bridge bind address. Leave as-is |

#### Config portal

| Variable | Default | Description |
|---|---|---|
| `WS_LOGIN_PATH` | `/login` | Path of the config portal page |
| `WS_LOGIN_PASS` | *(derived from `GOST_PASS`)* | Portal access password. If unset, auto-derived as SHA1(GOST_PASS+"wsgost")[:12]. Set explicitly to override |
| `WS_EXTERNAL_HOST` | *(auto from `Host` header)* | Public domain shown in share links. Leave unset on PaaS — the portal reads it from the request |
| `WS_EXTERNAL_PORT` | `443` | Public port shown in share links |
| `WS_EXTERNAL_TLS` | `true` | Include `security=tls` in Shadowsocks share links. Set `false` for plain HTTP setups |

#### Built-in DNS over HTTPS

| Variable | Default | Description |
|---|---|---|
| `WS_DNS_PATH` | `/dns-query` | Path of the RFC 8484 DoH endpoint. Set to `""` to disable |

The container runs a built-in **DNS-over-HTTPS (DoH)** resolver at `https://yourapp.platform.com/dns-query`. It accepts standard RFC 8484 GET and POST requests, forwards the raw DNS wire-format query to `8.8.8.8` / `1.1.1.1` / `8.8.4.4` **via DNS-over-TCP** on the server side, and returns the answer.

Because the DoH endpoint is on **the same host and port 443** as the proxy, it is reachable whenever the proxy itself is reachable — ISP UDP/53 blocking, DNS hijacking, and `DNS_PROBE_POSSIBLE` errors are all bypassed.

**Setup in v2raytun:**

1. Open v2raytun → **Settings → DNS**
2. Set DNS mode to **HTTPS (DoH)**
3. Paste the URL shown on your `/login` portal (e.g. `https://yourapp.onrender.com/dns-query`)
4. Set routing/detour for this DNS server to **direct** (not through the proxy — the DoH server is the same host as the proxy, so routing it through the proxy would be circular)
5. Save and reconnect

After this, every DNS query from every app and every browser on your phone resolves through the proxy's server network. `DNS_PROBE_POSSIBLE` and similar browser DNS errors go away entirely.

#### GOST proxy (internal)

| Variable | Default | Description |
|---|---|---|
| `GOST_SS_KEY` | *(disabled)* | Shadowsocks password. Setting this enables Shadowsocks on the same port and unlocks the QR code on `/login` |
| `GOST_SS_CIPHER` | `aes-256-gcm` | Shadowsocks cipher. `aes-256-gcm` is universally supported |
| `GOST_INTERNAL_PORT` | `18080` | Internal loopback port GOST listens on. No need to change |
| `GOST_MAX_CONN` | `200` | Max concurrent connections |
| `GOST_TIMEOUT` | `15` | Dial / connect timeout (seconds) |
| `GOST_IDLE_TIMEOUT` | `300` | Idle connection close timeout (seconds) |
| `GOST_FORCE_IPV4` | `true` | Prefer IPv4 for outbound traffic. Recommended on most cloud VMs |
| `GOST_ALLOW_NOAUTH` | `false` | Allow unauthenticated proxy connections. Leave `false` |

---

### Config portal — `/login`

The portal shows ready-made connection details and a scannable QR code. It is password-protected; the wrong password silently serves a fake landing page.

**How to find your portal password:**

The portal password defaults to the first 12 hex characters of SHA1(`GOST_PASS` + `"wsgost"`). The easiest way to get it is from the container startup log:

```
[wsgost] config portal : path=/login  pass=<your-portal-password>
[wsgost] access portal : https://<your-public-domain>/login?pass=<your-portal-password>
```

Or set it explicitly with `WS_LOGIN_PASS=anything`.

**Open the portal:**

```
https://yourapp.platform.com/login?pass=<your-portal-password>
```

The portal page shows:

- A QR code and `ss://` share link for v2rayNG / Shadowrocket / v2raytun (when `GOST_SS_KEY` is set)
- Manual Shadowsocks + WebSocket settings
- SOCKS5 / HTTP credentials for Clash Meta, Surge, etc.
- A bookmarkable URL of the portal itself (no port number — works on any PaaS)

---

### Connecting from client apps

Replace the placeholders:
- `yourapp.platform.com` → your actual public domain
- `/mysecretpath` → your `WS_PATH` value
- `myuser` / `strong-password` → your `GOST_USER` / `GOST_PASS`
- `your-ss-password` → your `GOST_SS_KEY` value

#### v2rayNG (Android) — Shadowsocks + WebSocket (recommended)

Fastest method: scan the QR code or paste the `ss://` link from your `/login` portal.

Manual setup:
1. Tap `+` → **Add Shadowsocks server**
2. Fill in:
   - **Address:** `yourapp.platform.com`
   - **Port:** `443`
   - **Encryption:** `aes-256-gcm`
   - **Password:** `your-ss-password`
3. Tap **More options** → set **Network** to `ws`
   - **Path:** `/mysecretpath`
   - **Host:** `yourapp.platform.com`
4. **TLS:** enabled — **SNI:** `yourapp.platform.com`
5. Save and connect.

#### Shadowrocket (iOS) — Shadowsocks + WebSocket

Fastest: scan the QR code from `/login`.

Manual setup:
1. Tap `+` → **Type: Shadowsocks**
2. **Host:** `yourapp.platform.com` / **Port:** `443`
3. **Password:** `your-ss-password` / **Method:** `aes-256-gcm`
4. **Obfs:** `websocket` / **Obfs Param:** `/mysecretpath`
5. Toggle TLS on.

#### v2raytun / Sing-box

Scan the QR code from `/login` or paste the `ss://` share link. The app auto-detects Shadowsocks + WebSocket + TLS from the URI.

#### Clash Meta / Mihomo

Add to your proxy configuration:

```yaml
proxies:
  - name: wsgost
    type: ss
    server: yourapp.platform.com
    port: 443
    cipher: aes-256-gcm
    password: your-ss-password
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      path: /mysecretpath
      tls: true
      host: yourapp.platform.com
      skip-cert-verify: false
```

#### Surge (iOS / macOS)

```ini
[Proxy]
wsgost = ss, yourapp.platform.com, 443, encrypt-method=aes-256-gcm, password=your-ss-password, obfs=websocket, obfs-uri=/mysecretpath, tls=true
```

#### Apps that only support raw SOCKS5 / HTTP (e.g. Super Proxy)

These apps send plain TCP directly — they do not speak WebSocket. They **cannot** connect to `:wsgost` without a local WebSocket tunnel shim. Use v2rayNG (Android) or Shadowrocket (iOS) instead, which handle WebSocket transport natively.

If you must use a SOCKS5-only app, run a local v2ray/Xray instance that exposes a local SOCKS5 port and connects upstream to `wss://yourapp.platform.com/mysecretpath`, then point the app to `127.0.0.1:local-socks5-port`.

---

Health check endpoint: `GET /health` → `200 ok`

## docker compose

Local test for SOCKS5 + HTTP:

```bash
docker compose up -d socks5 http-proxy
```

## Minimal OS compatibility

These images target Debian 13 slim style environments. Runtime dependencies are kept small:

- Proxy images (socks5, http-proxy): Python 3 + stdlib only
- GOST / WSGOST images: static Go binary + `ca-certificates`

## CI build

GitHub workflow file: `.github/workflows/build.yml`

- Builds all images (`socks5`, `http-proxy`, `gost`, `wsgost`) for `linux/amd64` and `linux/arm64`
- Pushes to GHCR on non-PR events
- Runs service-specific smoke checks

## Security notes

- Do not deploy with weak credentials.
- Store proxy credentials in platform secrets.
- Restrict inbound access with firewall/security groups.
- For WSGOST, set `WS_PATH` to a random secret path to avoid unauthenticated WS probing.

## Deployment references

- Quick start: `START-HERE.md`
- Claw deployment details: `CLAW-DEPLOYMENT.md`




