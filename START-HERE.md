# START HERE

Build and deploy one service per container.

## Services

- `:socks5` -> SOCKS5 proxy on port `1080`
- `:http-proxy` -> HTTP/HTTPS proxy on port `8080`
- `:wireguard` -> WireGuard VPN server on UDP `51820`

## Build

```bash
./build-all.sh
```

## Local quick test

```bash
docker compose up -d socks5 http-proxy
```

SOCKS5 test:

```bash
curl -x socks5://testuser:testpass@localhost:1080 https://ifconfig.me
```

HTTP test:

```bash
curl -x http://testuser:testpass@localhost:8080 https://ifconfig.me
```

## WireGuard quick run

```bash
docker run -d \
  --name wg-server \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 51820:51820/udp \
  -e WG_ENDPOINT=your.public.ip.or.domain:51820 \
  -v $(pwd)/wireguard-data:/etc/wireguard \
  proxy:wireguard
```

Generated clients will be in `./wireguard-data/clients`.

## Deploy docs

- Full reference: `README.md`
- Claw-specific settings: `CLAW-DEPLOYMENT.md`