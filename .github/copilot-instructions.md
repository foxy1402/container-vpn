# Copilot instructions for container-vpn

## Build, test, lint
- Build all images: `./build-all.sh`
- Build a single image:
  - `docker build -f Dockerfile -t proxy:socks5 .`
  - `docker build -f Dockerfile.http -t proxy:http-proxy .`
  - `docker build -f Dockerfile.gost -t proxy:gost .`
  - `docker build -f Dockerfile.wsgost -t proxy:wsgost .`
- Local compose (examples):
  - `docker compose up -d socks5 http-proxy`
  - `docker compose -f docker-compose-gost.yml up -d gost-proxy wsgost-proxy`
- Tests: no unit-test runner in repo; CI uses container smoke checks. Example single check (wsgost):
  ```
  docker run -d --name wsgost-test \
    -e WS_PROTOCOL=vless \
    -e VLESS_UUID=11111111-1111-1111-1111-111111111111 \
    -e WS_PATH=/ws \
    -p 127.0.0.1:38080:8080 \
    proxy:wsgost
  docker exec wsgost-test /app/wsgost-healthcheck.sh
  ```
- Lint: no lint configuration found.

## Architecture (big picture)
- Four independent images/services: SOCKS5, HTTP/HTTPS proxy, GOST multi-protocol proxy, and WSGOST (VLESS/Trojan over WebSocket). Each runs as its own container with separate ports and env config.
- `socks5_proxy.py` and `http_proxy.py` are Python stdlib proxies with env-based auth, connection limits, and self-healing bind retries.
- `gost-proxy.go` is a Go 1.22 binary that auto-detects protocol per connection (SOCKS5, HTTP CONNECT, optional Shadowsocks).
- WSGOST runs Xray-core with a runtime-generated config (`wsgost-start.sh`) and exposes a single WS listener for either VLESS or Trojan.
- Dockerfiles run everything as a non-root user on slim Debian images; GOST/WSGOST are static binaries (Go and Xray-core, respectively).

## Key conventions
- Configuration is entirely via environment variables, prefixed per service: `SOCKS5_*`, `HTTP_PROXY_*`, `GOST_*`, `WS_*`. WSGOST requires `WS_PROTOCOL` plus either `VLESS_UUID` or `TROJAN_PASSWORD`.
- Default ports: SOCKS5 `1080`, HTTP proxy `8080`, GOST/WSGOST `8080`. The compose file uses `8081`/`8082` host ports to avoid conflicts when running multiple services locally.
- WSGOST honors `PORT` (PaaS convention) ahead of `WS_PORT`, and enforces a leading `/` on `WS_PATH`.
- Health checks are service-specific: `/app/wsgost-healthcheck.sh` for WSGOST, `/app/gost-proxy-healthcheck.sh` for GOST, and socket-based checks for the Python proxies.
