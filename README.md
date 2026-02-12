# container-vpn

Cloud-ready container images for three independent services:

- SOCKS5 proxy (`:socks5`)
- HTTP/HTTPS proxy (`:http-proxy`)
- WireGuard VPN server (`:wireguard`)

Each service is deployed separately (one container per service).

## Published images (copy/paste)

- `ghcr.io/foxy1402/container-vpn:socks5`
- `ghcr.io/foxy1402/container-vpn:http-proxy`
- `ghcr.io/foxy1402/container-vpn:wireguard`

## Images and ports

| Image | Purpose | Port |
|---|---|---|
| `ghcr.io/foxy1402/container-vpn:socks5` | SOCKS5 with username/password auth | `1080/tcp` |
| `ghcr.io/foxy1402/container-vpn:http-proxy` | HTTP proxy + HTTPS CONNECT tunnel | `8080/tcp` |
| `ghcr.io/foxy1402/container-vpn:wireguard` | WireGuard server that auto-generates client configs | `51820/udp` |

## Build

Build all images:

```bash
./build-all.sh
```

Or build one:

```bash
docker build -f Dockerfile -t proxy:socks5 .
docker build -f Dockerfile.http -t proxy:http-proxy .
docker build -f Dockerfile.wireguard -t proxy:wireguard .
```

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

## 3) WireGuard VPN server

This image runs a WireGuard **server**, creates server keys if missing, and generates client profiles automatically.

### Required runtime capabilities

- `--cap-add=NET_ADMIN`
- `--device=/dev/net/tun`
- UDP port published (default `51820/udp`)

### Recommended persistence

Mount `/etc/wireguard` so server keys and generated clients survive container restarts.

### Optional env

- `WG_INTERFACE` (default `wg0`)
- `WG_PORT` (default `51820`)
- `WG_SERVER_CIDR` (default `10.66.66.1/24`)
- `WG_CLIENT_COUNT` (default `3`)
- `WG_CLIENT_PREFIX` (default `client`)
- `WG_ENDPOINT` (recommended in cloud, example `vpn.example.com:51820`)
- `WG_DNS` (default `1.1.1.1`)
- `WG_CLIENT_ALLOWED_IPS` (default `0.0.0.0/0,::/0`)
- `WG_PERSISTENT_KEEPALIVE` (default `25`)
- `WG_HEALTH_INTERVAL` (default `15`)

Recommended env block (copy/paste):

```yaml
WG_ENDPOINT: "your.public.domain.or.ip:51820"
WG_CLIENT_COUNT: "3"
WG_DNS: "1.1.1.1"
```

Run:

```bash
docker run -d \
  --name wireguard \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 51820:51820/udp \
  -e WG_ENDPOINT=vpn.example.com:51820 \
  -v $(pwd)/wireguard-data:/etc/wireguard \
  ghcr.io/foxy1402/container-vpn:wireguard
```

Generated client configs:

- `./wireguard-data/clients/client1/client1.conf`
- `./wireguard-data/clients/client2/client2.conf`
- ...

## docker compose

Local test for SOCKS5 + HTTP:

```bash
docker compose up -d socks5 http-proxy
```

WireGuard example config is included but commented in `docker-compose.yml` because it requires host networking capabilities.

## Minimal OS compatibility

These images target Debian 13 slim style environments. Runtime dependencies are kept small:

- Proxy images: Python 3 + stdlib only
- WireGuard image: `wireguard-tools`, `iproute2`, `iptables`, `procps`

## CI build

GitHub workflow file: `.github/workflows/build.yml`

- Builds all three images for `linux/amd64` and `linux/arm64`
- Pushes to GHCR on non-PR events
- Runs service-specific smoke checks

## Security notes

- Do not deploy with weak credentials.
- Store proxy credentials in platform secrets.
- Restrict inbound access with firewall/security groups.
- For WireGuard, explicitly set `WG_ENDPOINT` in cloud deployments.

## Deployment references

- Quick start: `START-HERE.md`
- Claw deployment details: `CLAW-DEPLOYMENT.md`
