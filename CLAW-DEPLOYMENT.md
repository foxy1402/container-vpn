# Claw Cloud Deployment Guide

This project publishes three separate images:

- `ghcr.io/<your-user>/<repo>:socks5`
- `ghcr.io/<your-user>/<repo>:http-proxy`
- `ghcr.io/<your-user>/<repo>:wireguard`

Use one image per app/pod.

## 1) SOCKS5 Proxy

Container port: `1080`

Required env:

```yaml
SOCKS5_USER: "your-username"
SOCKS5_PASS: "your-strong-password"
```

Optional env:

```yaml
SOCKS5_HOST: "0.0.0.0"
SOCKS5_PORT: "1080"
SOCKS5_MAX_CONN: "200"
SOCKS5_TIMEOUT: "15"
SOCKS5_IDLE_TIMEOUT: "300"
SOCKS5_AUTH_FAIL_LIMIT: "8"
SOCKS5_AUTH_FAIL_WINDOW: "60"
```

Test:

```bash
curl -x socks5://your-username:your-strong-password@your-app.claw.cloud:1080 https://ifconfig.me
```

## 2) HTTP/HTTPS Proxy

Container port: `8080`

Required env:

```yaml
HTTP_PROXY_USER: "your-username"
HTTP_PROXY_PASS: "your-strong-password"
```

Optional env:

```yaml
HTTP_PROXY_HOST: "0.0.0.0"
HTTP_PROXY_PORT: "8080"
HTTP_MAX_CONN: "200"
HTTP_PROXY_TIMEOUT: "30"
HTTP_PROXY_IDLE_TIMEOUT: "300"
HTTP_AUTH_FAIL_LIMIT: "8"
HTTP_AUTH_FAIL_WINDOW: "60"
```

Test:

```bash
curl -x http://your-username:your-strong-password@your-app.claw.cloud:8080 https://ifconfig.me
```

## 3) WireGuard VPN Server

Container UDP port: `51820`

Platform requirements:

- `NET_ADMIN` capability
- `/dev/net/tun` device
- UDP exposure for WireGuard port

WireGuard now runs as a server and generates client profiles automatically.

Optional env:

```yaml
WG_INTERFACE: "wg0"
WG_PORT: "51820"
WG_SERVER_CIDR: "10.66.66.1/24"
WG_CLIENT_COUNT: "3"
WG_CLIENT_PREFIX: "client"
WG_ENDPOINT: "your.public.ip.or.domain:51820"
WG_DNS: "1.1.1.1"
WG_CLIENT_ALLOWED_IPS: "0.0.0.0/0,::/0"
WG_PERSISTENT_KEEPALIVE: "25"
WG_HEALTH_INTERVAL: "15"
```

Notes:

- `WG_ENDPOINT` should be set explicitly for cloud deployments.
- Client files are created in `/etc/wireguard/clients/<client>/<client>.conf`.
- Mount `/etc/wireguard` to persistent storage to keep keys/profiles.

Suggested volume:

```yaml
volumes:
  - wireguard-data:/etc/wireguard
```

## Troubleshooting

1. App exits immediately: check required env vars are present.
2. Healthcheck failing: verify port mapping and that the process is listening.
3. WireGuard not starting: verify `NET_ADMIN` + `/dev/net/tun` + UDP port exposure.
4. WireGuard clients cannot connect: set `WG_ENDPOINT` to real public host/IP and open UDP `WG_PORT`.