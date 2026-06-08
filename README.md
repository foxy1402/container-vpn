# container-vpn

Cloud-ready container images for five independent services:

- SOCKS5 proxy (`:socks5`)
- HTTP/HTTPS proxy (`:http-proxy`)
- GOST multi-protocol proxy (`:gost`)
- WSGOST VLESS/Trojan over WebSocket (`:wsgost`)
- TLSGost SOCKS5+TLS / HTTP CONNECT+TLS proxy (`:tlsgost`)

Each service is deployed separately (one container per service).

## Published images (copy/paste)

- `ghcr.io/foxy1402/container-vpn:socks5`
- `ghcr.io/foxy1402/container-vpn:http-proxy`
- `ghcr.io/foxy1402/container-vpn:gost`
- `ghcr.io/foxy1402/container-vpn:wsgost`
- `ghcr.io/foxy1402/container-vpn:tlsgost`

## Images and ports

| Image | Purpose | Port |
|---|---|---|
| `ghcr.io/foxy1402/container-vpn:socks5` | SOCKS5 with username/password auth | `1080/tcp` |
| `ghcr.io/foxy1402/container-vpn:http-proxy` | HTTP proxy + HTTPS CONNECT tunnel | `8080/tcp` |
| `ghcr.io/foxy1402/container-vpn:gost` | Multi-protocol on one port (SOCKS5 + HTTP CONNECT + optional Shadowsocks) | `8080/tcp` |
| `ghcr.io/foxy1402/container-vpn:wsgost` | VLESS/Trojan over WebSocket — for platforms that only expose HTTP/HTTPS | `8080/tcp` |
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
docker build -f Dockerfile.wsgost -t proxy:wsgost .
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

### WSGOST (`:wsgost`)

- Name: `wsgost-proxy`
- Image: `ghcr.io/foxy1402/container-vpn:wsgost`
- Publish a new network port: host `8080` -> container `8080` (`tcp`)
- Environment variables:
  - `WS_PROTOCOL=vless` (or `trojan`)
  - `VLESS_UUID=your-uuid` (required when `WS_PROTOCOL=vless`)
  - `TROJAN_PASSWORD=your-password` (required when `WS_PROTOCOL=trojan`)
  - `WS_PATH=/your-secret-random-path`
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

## 4) WSGOST — VLESS/Trojan over WebSocket

Use this image on platforms that only expose **HTTP/HTTPS** (port 443) and do not allow raw TCP/UDP ports — Railway, Render, Fly.io, Koyeb, Zeabur, Northflank, etc. TLS is terminated by the platform; the container serves plain WebSocket on its internal port.

```
Client app (VLESS/Trojan over wss://) ──▶ Platform TLS edge ──▶ Xray (ws) in container
```

---

### Quick local test

```bash
docker run -d \
  --name wsgost \
  -p 8080:8080 \
  -e WS_PROTOCOL=vless \
  -e VLESS_UUID='11111111-1111-1111-1111-111111111111' \
  -e WS_PATH='/mysecretpath' \
  ghcr.io/foxy1402/container-vpn:wsgost
```

Verify it is up:

```bash
docker exec wsgost /app/wsgost-healthcheck.sh
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
4. Deploy.

> **Fly.io** — add `[[services]]` mapping internal port `8080` to external port `443` in `fly.toml`.  
> **Render** — set "Start Command" to `/app/wsgost-start.sh`; the image already has `CMD` set correctly.

---

### Environment variables

#### Required

| Variable | Description |
|---|---|
| `WS_PROTOCOL` | `vless` or `trojan` |
| `VLESS_UUID` | Required when `WS_PROTOCOL=vless` |
| `TROJAN_PASSWORD` | Required when `WS_PROTOCOL=trojan` |

#### Recommended

```yaml
WS_PROTOCOL: "vless"
VLESS_UUID: "your-uuid"
WS_PATH: "/your-secret-random-path"   # change this — keeps unauthenticated bots out
```

#### WebSocket listener

| Variable | Default | Description |
|---|---|---|
| `WS_PATH` | `/ws` | WebSocket endpoint path. **Set a random string** (e.g. `/xK9mQr`) for security |
| `PORT` / `WS_PORT` | `8080` | Container listen port. Platforms inject `PORT` automatically — leave unset |
| `WS_HOST` | `0.0.0.0` | Bind address. Leave as-is |

#### Logging

| Variable | Default | Description |
|---|---|---|
| `XRAY_LOG_LEVEL` | `warning` | Xray log level (`debug`, `info`, `warning`, `error`, `none`) |

---

### Connecting from client apps

Replace the placeholders:
- `yourapp.platform.com` → your actual public domain
- `/mysecretpath` → your `WS_PATH` value
- `your-uuid` / `your-password` → your `VLESS_UUID` or `TROJAN_PASSWORD`

#### VLESS over WebSocket

- **Address/Host:** `yourapp.platform.com`
- **Port:** `443`
- **Network/Transport:** `ws`
- **Path:** `/mysecretpath`
- **TLS:** enabled
- **UUID:** `your-uuid`

#### Trojan over WebSocket

- **Address/Host:** `yourapp.platform.com`
- **Port:** `443`
- **Network/Transport:** `ws`
- **Path:** `/mysecretpath`
- **TLS:** enabled
- **Password:** `your-password`

---

Health checks use a port-listening probe (`/app/wsgost-healthcheck.sh`). There is no HTTP `/health` endpoint.

## 5) TLSGost — SOCKS5+TLS / HTTP CONNECT+TLS proxy

This image wraps SOCKS5 and HTTP CONNECT inside TLS on a single port. Clients connect over TLS and the proxy auto-detects whether the inner protocol is SOCKS5 or HTTP CONNECT. If no TLS certificate is provided, a self-signed ECDSA P-256 certificate is generated at startup.

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
- WSGOST image: Xray-core binary + `ca-certificates`
- TLSGost image: static Go binary + `ca-certificates`

## CI build

GitHub workflow file: `.github/workflows/build.yml`

- Builds all images (`socks5`, `http-proxy`, `gost`, `wsgost`, `tlsgost`) for `linux/amd64` and `linux/arm64`
- Pushes to GHCR on non-PR events
- Runs service-specific smoke checks

## Security notes

- Do not deploy with weak credentials.
- Store proxy credentials in platform secrets.
- Restrict inbound access with firewall/security groups.
- For WSGOST, set `WS_PATH` to a random secret path to avoid unauthenticated WS probing.
- For TLSGost, always provide your own TLS certificate in production. Self-signed certs are for testing only.

## Deployment references

- Quick start: `START-HERE.md`
- Claw deployment details: `CLAW-DEPLOYMENT.md`

