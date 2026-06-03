# Vigil API Reference

Vigil exposes a single HTTPS server (default port 7020, configurable via `port`). All connections use TLS. The server has two auth tiers:

| Tier | Paths | Auth |
|------|-------|------|
| ACME | `/acme/*` | JWS (per-request account key signature, RFC 8555) |
| Admin | `/health`, `/ca`, `/certificates/*`, `/ocsp*`, `/crl*` | mTLS client certificate |

ACME endpoints do not require a TLS client certificate — authentication is embedded in each request body as a JSON Web Signature. Admin endpoints require a client certificate whose URI SAN matches an entry in `rbacIdentities` config.

---

## ACME Endpoints

These routes implement RFC 8555 (ACME). Every POST body is a JWS-encoded payload. The client proves account key possession on each request.

**Note:** Vigil's ACME state (nonces, orders, authorizations) is held in memory. A Vigil restart clears all in-progress orders.

### Route summary

| Method | Path | Description |
|--------|------|-------------|
| GET | `/acme/directory` | ACME directory |
| HEAD | `/acme/new-nonce` | Fresh nonce |
| GET | `/acme/new-nonce` | Fresh nonce |
| POST | `/acme/new-account` | Register account |
| POST | `/acme/account/:id` | Get account |
| POST | `/acme/new-order` | Create order |
| POST | `/acme/order/:id` | Get order status |
| POST | `/acme/order/:id/finalize` | Finalize with CSR |
| POST | `/acme/authz/:id` | Get authorization |
| POST | `/acme/challenge/:id` | Respond to challenge |
| POST | `/acme/cert/:id` | Download certificate |
| POST | `/acme/revoke-cert` | Revoke certificate |
| POST | `/acme/key-change` | Rotate account key |

---

#### GET /acme/directory

Returns the ACME directory object — the entry point for ACME clients. Contains URLs for all ACME operations.

Response: ACME directory JSON per RFC 8555 §7.1.1.

---

#### HEAD /acme/new-nonce
#### GET /acme/new-nonce

Returns a fresh anti-replay nonce in the `Replay-Nonce` response header. ACME clients call this before each signed request.

---

#### POST /acme/new-account

Registers a new ACME account or returns an existing one if the key is already registered.

Request body: JWS-encoded ACME new-account payload per RFC 8555 §7.3.

Response: ACME account object.

---

#### POST /acme/account/:id

Retrieves the ACME account identified by `:id`.

Request body: JWS-encoded (empty or update payload).

Response: ACME account object.

---

#### POST /acme/new-order

Creates a new certificate order for the specified identifiers.

Request body: JWS-encoded new-order payload:
```json
{
  "identifiers": [
    { "type": "dns", "value": "api.example.com" }
  ]
}
```

Response: ACME order object with `status: "pending"` and an `authorizations` list.

---

#### POST /acme/order/:id

Retrieves the current state of an order.

Request body: JWS-encoded (empty payload).

Response: ACME order object. `status` transitions: `pending` → `ready` → `processing` → `valid` (or `invalid`).

---

#### POST /acme/order/:id/finalize

Submits the CSR to finalize the order once all authorizations are satisfied.

Request body: JWS-encoded finalize payload:
```json
{ "csr": "<base64url-encoded DER CSR>" }
```

Response: Updated ACME order object with `status: "processing"` or `"valid"`.

---

#### POST /acme/authz/:id

Retrieves the authorization object, including the list of challenges.

Request body: JWS-encoded (empty payload).

Response: ACME authorization object with HTTP-01 challenge details.

---

#### POST /acme/challenge/:id

Signals to Vigil that the client is ready for challenge validation. Vigil will call out to verify the challenge (HTTP-01: fetches `/.well-known/acme-challenge/:token` on the domain).

Request body: JWS-encoded (empty payload `{}`).

Response: ACME challenge object. Poll the authorization URL to see when the challenge transitions to `valid`.

---

#### POST /acme/cert/:id

Downloads the issued certificate once the order is in `valid` state.

Request body: JWS-encoded (empty payload).

Response (`application/pem-certificate-chain`): PEM-encoded certificate chain.

---

#### POST /acme/revoke-cert

Revokes a certificate via ACME.

Request body: JWS-encoded revoke payload:
```json
{
  "certificate": "<base64url-encoded DER certificate>",
  "reason": 0
}
```

`reason` is an integer revocation reason code (0 = unspecified).

Response: `200` on success.

---

#### POST /acme/key-change

Rotates the account key.

Request body: Outer JWS wrapping an inner JWS per RFC 8555 §7.3.5.

Response: Updated ACME account object.

---

## Bootstrap Endpoint

#### POST /bootstrap

One-time initial PKI bootstrap. Used during the ceremony to enroll Vigil's own certificate before mTLS is available. This route is disabled once the CA is initialized.

Request body and response: depends on bootstrap phase; see `docs/bootstrap-guide.md`.

---

## Admin Endpoints (mTLS)

All routes below require a client certificate. The certificate's URI SAN is matched against `rbacIdentities` in `vigil.config.json`. Role hierarchy: `readonly` · `operator` · `admin`.

Revocation has role-conditional authorization: `admin` can revoke any certificate; non-admin callers can only revoke certificates they issued or own.

### Route summary

| Method | Path | Role |
|--------|------|------|
| GET | `/health` | Any authenticated |
| GET | `/ca` | Any authenticated |
| POST | `/certificates/sign` | Any authenticated |
| GET | `/certificates/:id` | Any authenticated |
| POST | `/certificates/:id/revoke` | Any authenticated (see note) |
| GET | `/ocsp/:id` | Any authenticated |
| GET | `/ocsp` | Any authenticated |
| POST | `/ocsp` | Any authenticated |
| GET | `/crl` | Any authenticated |
| GET | `/crl.der` | Any authenticated |
| GET | `/crl.pem` | Any authenticated |

---

#### GET /health

Returns service health with statistics about the CA, users, and certificates.

Response:
```json
{
  "status": "healthy",
  "service": "vigil",
  "users": { "total": 3 },
  "certificates": {
    "total": 42,
    "revoked": 1,
    "active": 41
  },
  "ca": {
    "initialized": true,
    "fingerprint256": "AABBCC...",
    "validTo": "2036-01-01T00:00:00Z"
  }
}
```

---

#### GET /ca

Returns metadata about the intermediate CA.

Response:
```json
{
  "rootCA": {
    "subject": "CN=Credo Intermediate CA",
    "fingerprint256": "AABBCC...",
    "validTo": "2036-01-01T00:00:00Z"
  }
}
```

---

#### POST /certificates/sign

Signs a CSR and issues a certificate. The CSR is validated against `issuancePolicy` (allowed DNS suffixes, URI prefixes, IP SANs). The certificate is stored in Vigil's database and the file system.

Request body:
```json
{
  "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "days": 365,
  "sans": ["www.api.example.com"]
}
```

`days` defaults to `ca.certDefaultDays` from config. `sans` is optional additional SANs to add beyond those in the CSR.

Response `201`:
```json
{
  "certificate": {
    "certPem": "-----BEGIN CERTIFICATE-----\n...",
    "id": "cert-abc123",
    "serialNumber": "01:AB:CD:EF",
    "subject": "CN=api.example.com",
    "validFrom": "2026-06-03T00:00:00Z",
    "validTo": "2027-06-03T00:00:00Z",
    "fingerprint256": "DDEEFF...",
    "issuedAt": "2026-06-03T12:00:00Z",
    "issuedBy": "shepherd",
    "ownerVigilUserId": "shepherd",
    "revoked": false
  }
}
```

---

#### GET /certificates/:id

Retrieves a certificate by its Vigil-internal ID.

Response:
```json
{
  "certificate": {
    "certPem": "-----BEGIN CERTIFICATE-----\n...",
    "id": "cert-abc123",
    "serialNumber": "01:AB:CD:EF",
    "subject": "CN=api.example.com",
    "revoked": false
  }
}
```

Returns `404` if the ID is unknown or the certificate file is missing.

---

#### POST /certificates/:id/revoke

Revokes a certificate. Admin callers may revoke any certificate. Non-admin callers may only revoke certificates they issued or own; `403` is returned otherwise.

Request body:
```json
{ "reason": "superseded" }
```

`reason` is optional (defaults to `"unspecified"`). Common values: `"unspecified"`, `"keyCompromise"`, `"superseded"`, `"cessationOfOperation"`.

Response:
```json
{
  "certificate": {
    "id": "cert-abc123",
    "revoked": true,
    ...
  }
}
```

---

#### GET /ocsp/:id

Returns OCSP status for the certificate identified by Vigil ID.

Response:
```json
{
  "ocsp": {
    "status": "good",
    "serialNumber": "01:AB:CD:EF",
    "revokedAt": null,
    "revocationReason": null
  }
}
```

---

#### GET /ocsp?serialNumber=:serial

Returns OCSP status by certificate serial number (hex string).

Response: same shape as `GET /ocsp/:id`.

---

#### POST /ocsp

Processes a DER-encoded OCSP request and returns a DER-encoded OCSP response. For use by TLS clients and OCSP staplers that speak the standard wire protocol.

Request body: raw DER bytes (`Content-Type: application/ocsp-request`).

Response (`application/ocsp-response`): raw DER bytes. Returns `400` if the request is empty or malformed.

---

#### GET /crl

Returns the current Certificate Revocation List as JSON.

Response:
```json
{
  "crl": {
    "thisUpdate": "2026-06-03T00:00:00Z",
    "nextUpdate": "2026-06-04T00:00:00Z",
    "revokedCertificates": [
      {
        "serialNumber": "01:AB:CD:EF",
        "revocationDate": "2026-06-02T10:00:00Z",
        "reason": "keyCompromise"
      }
    ]
  }
}
```

---

#### GET /crl.der

Returns the CRL in DER format.

Response (`application/pkix-crl`, `Content-Disposition: inline; filename="vigil.crl"`): raw DER bytes.

---

#### GET /crl.pem

Returns the CRL in PEM format.

Response (`application/x-pem-file`, `Content-Disposition: inline; filename="vigil.crl.pem"`): PEM-encoded CRL.
