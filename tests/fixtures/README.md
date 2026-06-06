# Test PKI Fixtures

**TEST USE ONLY — never deploy these keys in production.**

This directory contains a pre-generated two-tier CA hierarchy used by the credo
test suite. Certs use the reserved `.credo.test` domain (RFC 2606) and are
explicitly labelled "Test" in their subject names.

## Files

| File | Description |
|------|-------------|
| `root-ca.pem` | Self-signed root CA certificate (10-year validity) |
| `root-ca.key` | Root CA private key (unencrypted, test-only) |
| `intermediate-ca.pem` | Intermediate CA certificate signed by root (10-year validity) |
| `intermediate-ca.key` | Intermediate CA private key (unencrypted, test-only) |
| `catrust.pem` | Trust anchor bundle (= root-ca.pem) distributed to test services |

## Regeneration

These files are committed so test runs have no runtime openssl dependency.
Regenerate only if the certs expire (2036) or the CA hierarchy needs to change:

```bash
cargo run -p gen-fixtures -- tests/fixtures
```

Verify the new chain before committing:

```bash
openssl verify -CAfile tests/fixtures/catrust.pem tests/fixtures/intermediate-ca.pem
```

The generator lives at `tools/gen-fixtures/`.
