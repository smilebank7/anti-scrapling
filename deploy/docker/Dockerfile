# syntax=docker/dockerfile:1

# ─── Stage 1: JS bundle ───────────────────────────────────────────────────────
FROM node:20-alpine AS jsbuild
WORKDIR /src
COPY web/challenge/package*.json web/challenge/tsconfig.json web/challenge/esbuild.config.mjs ./
COPY web/challenge/src ./src
COPY web/challenge/index.html ./
RUN npm ci && npm run build

# ─── Stage 2: Go build ────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS gobuild
RUN apk add --no-cache git make
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=jsbuild /src/dist/challenge.bundle.js internal/challenge/assets/challenge.bundle.js
COPY --from=jsbuild /src/dist/index.html internal/challenge/assets/index.html
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
      -o /out/antiscrapling \
      ./cmd/antiscrapling
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/antiscrapling-cli \
      ./cmd/antiscrapling-cli

# ─── Stage 3: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3.21
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 65532 nonroot
COPY --from=gobuild /out/antiscrapling     /usr/local/bin/antiscrapling
COPY --from=gobuild /out/antiscrapling-cli /usr/local/bin/antiscrapling-cli
COPY policies/default.yaml /etc/anti-scrapling/policy.yaml
RUN mkdir -p /var/lib/anti-scrapling \
    && chown -R nonroot:nonroot /etc/anti-scrapling /var/lib/anti-scrapling
USER nonroot
EXPOSE 8080 9090 9091
ENTRYPOINT ["/usr/local/bin/antiscrapling"]
CMD ["--config", "/etc/anti-scrapling/policy.yaml"]
