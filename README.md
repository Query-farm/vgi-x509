<p align="center">
  <img src="docs/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A <a href="https://query.farm">Query.Farm</a> VGI worker for DuckDB.</em></p>

# vgi-x509

[![CI](https://github.com/Query-farm/vgi-x509/actions/workflows/ci.yml/badge.svg)](https://github.com/Query-farm/vgi-x509/actions/workflows/ci.yml)

A [VGI](https://query.farm) worker, written in **Go**, that parses **X.509
certificates** and inspects **TLS endpoints** — all exposed as DuckDB/SQL
functions. It is a defensive **security / compliance** tool: certificate
inventory, expiry monitoring, and endpoint inspection.

Built on the [`vgi-go`](https://github.com/Query-farm/vgi-go) SDK; speaks the
VGI protocol over stdio. Catalog name: `x509`.

```sql
INSTALL vgi FROM community; LOAD vgi;

-- LOCATION is the path to the compiled worker binary.
ATTACH 'x509' AS x509 (TYPE vgi, LOCATION '/path/to/vgi-x509-worker');

-- Parse a certificate (PEM text or DER bytes work everywhere):
SELECT x509.cert_subject(pem), x509.cert_not_after(pem), x509.cert_is_expired(pem)
FROM my_certs;

-- Subject alternative names as a list:
SELECT x509.cert_sans(pem) FROM my_certs;

-- Long-format dump of one certificate:
SELECT field, value FROM x509.cert_info('-----BEGIN CERTIFICATE-----...');

-- Inspect a live TLS endpoint (AUTHORIZED endpoints only — see below):
SELECT seq, subject, not_after, fingerprint
FROM x509.tls_inspect('example.com:443');
```

## Input: PEM or DER

Every certificate-parsing function accepts a certificate as **either** a PEM
text string (`VARCHAR`) **or** raw DER bytes (`BLOB`). The argument is declared
with Arrow type `any`, and the worker sniffs the content: input that begins with
the `-----BEGIN` PEM armor is decoded as PEM, otherwise it is treated as DER. So
the same SQL function works regardless of how your certificate column is stored.

Malformed input (empty, non-base64 PEM body, wrong PEM block type, or invalid
DER) produces a **clear SQL error** rather than a crash. A SQL `NULL` certificate
yields a `NULL` result (scalars) or zero rows (`cert_info`).

## Functions

### Certificate scalars

| Function | Returns | Description |
| --- | --- | --- |
| `cert_subject(cert)` | `VARCHAR` | Subject as an RFC 2253 distinguished name |
| `cert_issuer(cert)` | `VARCHAR` | Issuer as an RFC 2253 distinguished name |
| `cert_serial(cert)` | `VARCHAR` | Serial number (decimal string; serials exceed 64 bits) |
| `cert_not_before(cert)` | `TIMESTAMP` | Start of the validity window (UTC) |
| `cert_not_after(cert)` | `TIMESTAMP` | End of the validity window (UTC) |
| `cert_is_expired(cert)` | `BOOLEAN` | Whether the cert is outside its validity window *now* |
| `cert_key_algorithm(cert)` | `VARCHAR` | Public-key algorithm + size/curve, e.g. `RSA-2048`, `ECDSA-P256`, `Ed25519` |
| `cert_signature_algorithm(cert)` | `VARCHAR` | Signature algorithm, e.g. `ECDSA-SHA256` |
| `cert_fingerprint(cert)` | `VARCHAR` | SHA-256 fingerprint of the DER (lowercase hex) |
| `cert_is_ca(cert)` | `BOOLEAN` | Whether the cert is a CA (BasicConstraints) |
| `cert_sans(cert)` | `VARCHAR[]` | Subject alternative names: DNS names then IP addresses |

### Table functions

`cert_info(cert) -> (field VARCHAR, value VARCHAR)` — long-format dump of every
attribute above for one certificate, one row per field.

```sql
SELECT field, value FROM x509.cert_info('-----BEGIN CERTIFICATE-----...');
```

`tls_inspect(host_port) -> (seq INT, subject, issuer, not_before TIMESTAMP, not_after TIMESTAMP, is_ca BOOLEAN, fingerprint)`
— connect to a TLS endpoint (`host:port`) and return the **certificate chain the
server presents**, one row per certificate in presentation order (`seq = 0` is
the leaf). Named options:

| Option | Default | Meaning |
| --- | --- | --- |
| `timeout_ms` | `10000` | Dial + handshake timeout in milliseconds |
| `insecure` | `true` | Skip chain verification — we are *inspecting*, not trusting |
| `server_name` | `NULL` | SNI server name (defaults to the host portion of `host:port`) |

```sql
SELECT seq, subject, not_after FROM x509.tls_inspect('example.com:443');
```

A connection or handshake failure (including a timeout) surfaces a clean SQL
error; the function never hangs. A `NULL` `host_port` yields zero rows.

> **`tls_inspect` is for endpoints you are AUTHORIZED to inspect.** It opens a
> network connection to the supplied `host:port`. Only point it at hosts you own
> or have explicit permission to probe. It does **not** verify the chain by
> default (`insecure := true`), because the purpose is to inspect whatever a
> server presents — including expired or self-signed certificates.

## Build & test

```sh
make build       # build the worker + mock-TLS-server binaries
make test-unit   # pure-Go unit tests
make test-sql    # haybarn-unittest SQL E2E against a local mock TLS server
make test        # both
```

`test-sql` needs [`haybarn-unittest`](https://pypi.org/project/haybarn-unittest/)
on `PATH`:

```sh
uv tool install haybarn-unittest
export PATH="$HOME/.local/bin:$PATH"
```

The cert-parsing scalars and `cert_info` are pure (no network) and are tested in
SQL against a committed PEM fixture. `tls_inspect` is tested against a tiny mock
TLS server (`cmd/mockserver`) that presents a generated self-signed certificate;
the `Makefile`'s `test-sql` target starts it on a free port, points the test at
it via `VGI_X509_TEST_ADDR`, and stops it afterward.

## Licensing

- This worker is licensed under the **MIT License** — see [`LICENSE`](./LICENSE).
- Certificate parsing and TLS inspection use only the **Go standard library**
  (`crypto/x509`, `encoding/pem`, `crypto/tls`) — no third-party crypto.
- The VGI SDK [`vgi-go`](https://github.com/Query-farm/vgi-go) is a separate
  dependency under its own license (the Query Farm Source-Available License).

---

## Authorship & License

Written by [Query.Farm](https://query.farm) — every VGI worker is designed and built by Query.Farm.

Copyright 2026 Query Farm LLC - https://query.farm

