# Copilot instructions for container-vpn

## Build, test, lint
- Build all images: `./build-all.sh`
- Build a single image:
  - `docker build -f Dockerfile -t proxy:socks5 .`
  - `docker build -f Dockerfile.http -t proxy:http-proxy .`
  - `docker build -f Dockerfile.gost -t proxy:gost .`
  - `docker build -f Dockerfile.metrics-gateway -t proxy:metrics-gateway .`
  - `docker build -f Dockerfile.tlsgost -t proxy:tlsgost .`
- Local compose (examples):
  - `docker compose up -d socks5 http-proxy`
  - `docker compose -f docker-compose-gost.yml up -d gost-proxy metrics-gateway`
- Tests: no unit-test runner in repo; CI uses container smoke checks. Example single check (metrics-gateway):
  ```
  docker run -d --name metrics-gateway-test \
    -e SERVICE_MODE=standard \
    -e SERVICE_TOKEN=11111111-1111-1111-1111-111111111111 \
    -e SERVICE_ENDPOINT=/api/v1/metrics \
    -p 127.0.0.1:38080:8080 \
    proxy:metrics-gateway
  docker exec metrics-gateway-test /app/service-healthcheck.sh
  ```
- Lint: no lint configuration found.

## Architecture (big picture)
- Five independent images/services: SOCKS5, HTTP/HTTPS proxy, GOST multi-protocol proxy, Metrics Gateway (VLESS/Trojan over WebSocket), and TLSGost (SOCKS5+TLS / HTTP CONNECT+TLS). Each runs as its own container with separate ports and env config.
- `socks5_proxy.py` and `http_proxy.py` are Python stdlib proxies with env-based auth, connection limits, and self-healing bind retries.
- `gost-proxy.go` is a Go 1.22 binary that auto-detects protocol per connection (SOCKS5, HTTP CONNECT, optional Shadowsocks).
- `metrics-gateway.go` is a Go binary that accepts WebSocket connections and forwards them to the internal Xray-core processor.
- Metrics Gateway runs Xray-core with a runtime-generated config (`metrics-gateway-start.sh`) and exposes a single WS listener for either VLESS or Trojan.
- `tlsgost-proxy.go` is a Go binary that wraps SOCKS5 and HTTP CONNECT inside TLS on a single port with auto-detection.
- Dockerfiles run everything as a non-root user on slim Debian images; GOST/Metrics Gateway/TLSGost are static binaries (Go and Xray-core, respectively).

## Key conventions
- Configuration is entirely via environment variables, prefixed per service: `SOCKS5_*`, `HTTP_PROXY_*`, `GOST_*`, `SERVICE_*`, `TLSGOST_*`. Metrics Gateway requires `SERVICE_MODE` plus either `SERVICE_TOKEN` (standard/VLESS) or `SERVICE_CREDENTIAL` (enhanced/Trojan).
- Default ports: SOCKS5 `1080`, HTTP proxy `8080`, GOST/Metrics Gateway `8080`, TLSGost `8443`. The compose file uses `8081`/`8082` host ports to avoid conflicts when running multiple services locally.
- Metrics Gateway honors `PORT` (PaaS convention) ahead of `SERVICE_PORT`, and enforces a leading `/` on `SERVICE_ENDPOINT`.
- Health checks are service-specific: `/app/service-healthcheck.sh` for Metrics Gateway, `/app/gost-proxy-healthcheck.sh` for GOST, `/app/tlsgost-healthcheck.sh` for TLSGost, and socket-based checks for the Python proxies.
