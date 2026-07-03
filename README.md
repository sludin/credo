# credo

`credo` is a hub-and-spoke TLS certificate management system written in Rust. It provides centralized certificate orchestration and lifecycle management across multiple machines using a pull-based reconciliation model.

**Services:**

- **shepherd** — central coordinator (control plane)
- **corgi** — distributed agent running on each managed node
- **vigil** — private ACME-compatible certificate authority
- **dashboard** — React+Vite management UI with Express BFF
- **ceremony** — offline PKI ceremony scripts for root/intermediate CA generation

**Service Ports:**

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| Shepherd | 7010 | mTLS | Agent port — Corgi pulls assignments and delivers CSRs |
| Shepherd | 7011 | HTTPS | Dashboard port — JWT Bearer or mTLS client cert auth |
| Corgi | 7001 | mTLS | Corgi control API |
| Corgi | 8080 | HTTP | HTTP-01 ACME challenge listener |
| Vigil | 7020 | mTLS | ACME and admin endpoints |
| Dashboard | 7030 | HTTPS | React SPA + Express BFF |

## Documentation

See [docs/README.md](docs/README.md) for the full documentation index: bootstrap guide, architecture, security, config reference, API reference, and troubleshooting.

## License

MIT
