# Anti-Scrapling

**Security middleware that defeats modern web scraping toolchains.**

Anti-Scrapling is a drop-in HTTP firewall that detects and blocks sophisticated scraping libraries (Scrapling, curl-impersonate, undetected-playwright, camoufox) by layering TLS fingerprinting, HTTP/2 detection, browser-fingerprint challenges, behavioral analysis, and IP reputation.

## Status

Active development. See `docs/` for architecture and threat model.

## Quick start

```bash
docker run -p 8080:8080 ghcr.io/anti-scrapling/anti-scrapling:latest
```

## Documentation

- [Threat Model](docs/01-threat-model.md)
- [Architecture](docs/02-architecture.md)
- [Build Plan](docs/03-build-plan.md)

## License

Apache-2.0
