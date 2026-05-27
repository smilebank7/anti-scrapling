# Docker Deployment

## Image

`ghcr.io/smilebank7/anti-scrapling:<tag>`

Multi-stage build: Node 20 Alpine (JS bundle) → Go 1.25 Alpine (binaries) → Alpine 3.21 (runtime).

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | HTTP | Proxy / challenge endpoint |
| 9090 | HTTP | Admin API (antiscrapling-cli target) |
| 9091 | HTTP | Prometheus metrics (`/metrics`) |

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AS_TARGET` | Yes | Upstream origin URL, e.g. `http://backend:3000` |
| `AS_TOKEN_SECRET_FILE` | No | Path to file containing HMAC secret for challenge tokens |
| `AS_CONFIG` | No | Override config path (default `/etc/anti-scrapling/policy.yaml`) |

## Mounting config

The default policy is baked in at `/etc/anti-scrapling/policy.yaml`. Override by bind-mounting your own:

```bash
docker run -p 8080:8080 \
  -e AS_TARGET=http://upstream:3000 \
  -v $(pwd)/my-policy.yaml:/etc/anti-scrapling/policy.yaml:ro \
  ghcr.io/smilebank7/anti-scrapling:latest
```

## Quick start with docker compose

```bash
cp docker-compose.example.yaml docker-compose.yaml
echo "$(openssl rand -hex 32)" > token.key
docker compose up
```

## Build locally

```bash
docker build -f deploy/docker/Dockerfile -t anti-scrapling:dev .
```

## Image size

~25–35 MB (Alpine runtime + statically-linked Go binaries, no CGO).
