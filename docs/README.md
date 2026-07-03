# Credo Documentation

## Getting Started
- [Bootstrap Guide](bootstrap-guide.md) — End-to-end setup from PKI ceremony to running services
- [Ceremony Guide](../ceremony/README.md) — Offline CA ceremony: when, why, and how to run it

## Architecture
- [Architecture](architecture.md) — System topology, cert lifecycle, pull-based model, mTLS auth

## Security
- [Security Defaults](security-defaults.md) — What's enforced out of the box vs. what requires operator action
- [Operator Hardening](operator-hardening.md) — Production hardening checklist for all services
- [Security Design](roadmap/security.md) — Full threat model and cryptographic choices

## Configuration Reference
- [Config Overview](config-overview.md) — All config files, their purpose, env var overrides, and reload behavior
- [Example Configs](examples/) — Working config skeletons for all services
- Shepherd: [config](../shepherd/docs/config.md) · [API](../shepherd/docs/api.md) · [CLI](../shepherd/docs/cli.md)
- Corgi: [config](../corgi/docs/config.md) · [API](../corgi/docs/api.md) · [CLI](../corgi/docs/cli.md)
- Vigil: [config](../vigil/docs/config.md) · [API](../vigil/docs/api.md) · [CLI](../vigil/docs/cli.md)
- Dashboard: [config](../dashboard/docs/config.md) · [CLI](../dashboard/docs/cli.md)

## Operations
- [Troubleshooting](troubleshooting.md) — Failure scenarios and recovery steps
- [Dashboard Guide](dashboard-guide.md) — Dashboard deployment and WebAuthn/passkey setup

## Deployment Notes
- [Synology](deploy/synology.md) — Synology DS918+ cross-compilation and deployment notes
