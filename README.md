<p align="center">
  <img src="https://query.farm/media-kit/products/vgi/vgi-logo.png" alt="Vector Gateway Interface (VGI)" width="320">
</p>

<p align="center"><em>A <a href="https://query.farm">Query.Farm</a> VGI worker for DuckDB.</em></p>

# Parse X.509 Certificates, Inspect TLS Endpoints & Search CT Logs in DuckDB

> **vgi-x509** · a [Query.Farm](https://query.farm) VGI worker

[![CI](https://github.com/Query-farm/vgi-x509/actions/workflows/ci.yml/badge.svg)](https://github.com/Query-farm/vgi-x509/actions/workflows/ci.yml)

A [VGI](https://query.farm) worker, written in **Go**, that parses **X.509
certificates**, inspects **TLS endpoints** and searches **Certificate
Transparency logs** — all exposed as DuckDB/SQL functions. It is a defensive
**security / compliance** tool: certificate inventory, expiry monitoring,
endpoint inspection, and discovering every certificate issued for your domains.

Built on the [`vgi-go`](https://github.com/Query-farm/vgi-go) SDK; speaks the
VGI protocol over stdio. Catalog name: `x509`.

```sql
INSTALL vgi FROM community; LOAD vgi;

ATTACH 'x509' AS x509 (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-x509@v0.5.1');

-- my_certs is your own table with a pem column (PEM text or DER bytes).
-- Parse a certificate:
SELECT x509.cert_subject(pem), x509.cert_not_after(pem), x509.cert_is_expired(pem)
FROM my_certs;

-- Subject alternative names as a list:
SELECT x509.cert_sans(pem) FROM my_certs;

-- Long-format dump of one certificate (a table function takes a constant, so
-- paste the whole PEM text in place of <PEM>):
SELECT field, value FROM x509.cert_info('<PEM>');

-- Inspect a live TLS endpoint (AUTHORIZED endpoints only — see below):
SELECT seq, subject, not_after, fingerprint
FROM x509.tls_inspect('example.com:443');

-- Every certificate Certificate Transparency logs hold for your subdomains
-- (passive: queries crt.sh, never your hosts):
SELECT id, common_name, sans, not_after
FROM x509.ct_search('%.example.com', exclude_expired := true, deduplicate := true);
```

## Quick start

Every [GitHub release](https://github.com/Query-farm/vgi-x509/releases) ships a prebuilt worker binary. The `vgi` extension downloads the one for your platform, checks its SHA-256 and caches it, so there is nothing to install besides DuckDB:

```sql
INSTALL vgi FROM community;
LOAD vgi;

ATTACH 'x509' AS x509 (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-x509@v0.5.1');

-- Read the subject distinguished name of a certificate.
SELECT x509.main.cert_subject('-----BEGIN CERTIFICATE-----
MIIB3DCCAYGgAwIBAgIEOt5osTAKBggqhkjOPQQDAjA7MRkwFwYDVQQKExBWR0kg
WDUwOSBGaXh0dXJlMR4wHAYDVQQDExV0ZXN0LnZnaS14NTA5LmV4YW1wbGUwHhcN
MjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA7MRkwFwYDVQQKExBWR0kgWDUw
OSBGaXh0dXJlMR4wHAYDVQQDExV0ZXN0LnZnaS14NTA5LmV4YW1wbGUwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAS7Zbq+Bz73Y0wKrZZkw4owgz7qyAtXYUrNUkac
Ot2h1WpF/Y+ODgRoeo0+ixbqPxA8+Lm9DTpksjsxTMRni/Owo3MwcTAOBgNVHQ8B
Af8EBAMCAoQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADA8BgNV
HREENTAzghV0ZXN0LnZnaS14NTA5LmV4YW1wbGWCFGFsdC52Z2kteDUwOS5leGFt
cGxlhwR/AAABMAoGCCqGSM49BAMCA0kAMEYCIQCGCty4v7uWVHE/HhanzxE2kzBo
KBiJ1j25vqPbFP4x7AIhAPdzfBNzgiIxriWsiBH1HBtoOCRsMJ6WN+j7zxyn9Np0
-----END CERTIFICATE-----') AS subject;

-- Flag a certificate that is currently outside its validity window.
SELECT x509.main.cert_is_expired('-----BEGIN CERTIFICATE-----
MIIB3DCCAYGgAwIBAgIEOt5osTAKBggqhkjOPQQDAjA7MRkwFwYDVQQKExBWR0kg
WDUwOSBGaXh0dXJlMR4wHAYDVQQDExV0ZXN0LnZnaS14NTA5LmV4YW1wbGUwHhcN
MjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA7MRkwFwYDVQQKExBWR0kgWDUw
OSBGaXh0dXJlMR4wHAYDVQQDExV0ZXN0LnZnaS14NTA5LmV4YW1wbGUwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAS7Zbq+Bz73Y0wKrZZkw4owgz7qyAtXYUrNUkac
Ot2h1WpF/Y+ODgRoeo0+ixbqPxA8+Lm9DTpksjsxTMRni/Owo3MwcTAOBgNVHQ8B
Af8EBAMCAoQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADA8BgNV
HREENTAzghV0ZXN0LnZnaS14NTA5LmV4YW1wbGWCFGFsdC52Z2kteDUwOS5leGFt
cGxlhwR/AAABMAoGCCqGSM49BAMCA0kAMEYCIQCGCty4v7uWVHE/HhanzxE2kzBo
KBiJ1j25vqPbFP4x7AIhAPdzfBNzgiIxriWsiBH1HBtoOCRsMJ6WN+j7zxyn9Np0
-----END CERTIFICATE-----') AS is_expired;
```

Prebuilt binaries cover macOS (Apple silicon), Linux (x86-64 and arm64) and Windows (x86-64). `github-auto://` needs an explicit release tag; change `@v0.5.1` to move to a newer release.

### Other ways to run it

- **Docker** (the image bundles the worker; needs a container runtime):

  ```sql
  ATTACH 'x509' AS x509 (TYPE vgi, LOCATION 'docker://ghcr.io/query-farm/vgi-x509:0.5.1');
  ```

- **Manual download.** Download the archive for your platform from the [releases page](https://github.com/Query-farm/vgi-x509/releases), verify it against its `.sha256` file (a cosign `.cosign.bundle` is published alongside), unpack it, and set `LOCATION` to the path of the extracted worker executable.

### Build from source

To build the worker yourself, see [Build & test](#build--test).

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
| `cert_key_algorithm(cert)` | `VARCHAR` | Public-key algorithm + size/curve, e.g. `RSA-2048`, `ECDSA-P256`, `Ed25519`, `X25519`; `Unknown` for an unrecognised algorithm |
| `cert_signature_algorithm(cert)` | `VARCHAR` | Signature algorithm, e.g. `ECDSA-SHA256`, `SHA256-RSA`; `Unknown` for an unrecognised OID |
| `cert_fingerprint(cert)` | `VARCHAR` | SHA-256 fingerprint of the DER (lowercase hex) |
| `cert_is_ca(cert)` | `BOOLEAN` | Whether the cert is a CA (BasicConstraints) |
| `cert_sans(cert)` | `VARCHAR[]` | Subject alternative names: DNS names then IP addresses |

### Table functions

`cert_info(cert) -> (field VARCHAR, value VARCHAR)` — long-format dump of every
attribute above for one certificate, one row per field.

```sql
SELECT field, value FROM x509.cert_info('<PEM>');  -- <PEM>: the full PEM text
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

### Certificate Transparency search

`ct_search(query) -> (id BIGINT, issuer_ca_id BIGINT, issuer_name, common_name, sans VARCHAR[], serial_number, not_before TIMESTAMP, not_after TIMESTAMP, entry_timestamp TIMESTAMP, pem)`
— search the public [Certificate Transparency](https://certificate.transparency.dev/)
logs through the free, keyless [crt.sh](https://crt.sh/) JSON API and return one
row per logged certificate, newest first (crt.sh `id` descending). `query` is an
exact domain (`example.com`) or a SQL LIKE pattern (`%.example.com` for every
subdomain). `sans` is crt.sh's newline-separated `name_value` split into a list;
`serial_number` is lowercase hex as crt.sh reports it (`cert_serial` returns the
same number in decimal). All timestamps are UTC. Named options:

| Option | Default | Meaning |
| --- | --- | --- |
| `exclude_expired` | `false` | Drop certificates already past `not_after` (crt.sh `exclude=expired`) |
| `deduplicate` | `false` | One row per certificate instead of precertificate + final certificate (crt.sh `deduplicate=Y`) |
| `max_results` | `0` | Keep only the newest N entries (0 = all) |
| `include_certificate` | `false` | Also download each certificate into `pem` (one extra request per row, at most 100 rows) |
| `timeout_ms` | `60000` | Timeout for each crt.sh HTTP attempt |
| `max_retries` | `3` | Retries on HTTP 429 / 5xx / network errors, with exponential backoff (honours a short `Retry-After`) |
| `base_url` | `NULL` | A crt.sh mirror or test server instead of `https://crt.sh/` |

`ct_certificate(id) -> VARCHAR` downloads the certificate crt.sh logged under
an id (`https://crt.sh/?d=<id>`) as PEM text, so it composes with every
`cert_*` scalar; an id crt.sh does not know yields NULL. `ct_certificate(id,
base_url)` targets a mirror or test server.

```sql
-- Key and signature algorithms of every unexpired certificate issued for a domain.
SELECT c.id, c.common_name, c.not_after,
       x509.cert_key_algorithm(x509.ct_certificate(c.id)) AS key_algorithm,
       x509.cert_signature_algorithm(x509.ct_certificate(c.id)) AS signature_algorithm
FROM x509.ct_search('example.com', exclude_expired := true, deduplicate := true) AS c;

-- The same in one call, downloading inside ct_search:
SELECT common_name, x509.cert_sans(pem)
FROM x509.ct_search('example.com', deduplicate := true, max_results := 10,
                    include_certificate := true);
```

> **Passive, public data.** `ct_search` and `ct_certificate` query crt.sh, a
> public index of the CT logs. They never connect to the hosts being searched
> for, so unlike `tls_inspect` they need no authorization from the domain owner.
> crt.sh is a free community service that is often slow and answers HTTP 429 /
> 502 under load: keep wildcard queries narrow, and expect an occasional clear
> "crt.sh answered HTTP 5xx after N attempt(s)" error. The worker does not
> depend on SSLMate's commercial CT API.

**Sample log.** The reserved domain `vgi-x509.example` (RFC 2606 `.example`
names cannot be issued by any CA, so crt.sh never holds entries for them) is
answered offline from a built-in sample log over the worker's two committed
fixture certificates, as are its crt.sh ids `9100000000000000001`–`…003`. That
keeps the published examples and agent tasks runnable when crt.sh is down. It
applies only to the default endpoint; with `base_url` every query goes over HTTP.

```sql
SELECT c.common_name, c.not_after,
       x509.cert_key_algorithm(x509.ct_certificate(c.id)) AS key_algorithm
FROM x509.ct_search('%.vgi-x509.example', deduplicate := true) AS c
ORDER BY c.not_after;
-- legacy.vgi-x509.example  2016-01-01 00:00:00  RSA-1024
-- test.vgi-x509.example    2035-01-01 00:00:00  ECDSA-P256
```

### Combining functions

The scalars compose over a column of certificates, so one query can audit a
whole inventory. Given a table `my_certs(name, pem)` (PEM text or DER bytes),
this lists every certificate by expiry with its policy findings:

```sql
SELECT name,
       x509.main.cert_not_after(pem) AS not_after,
       x509.main.cert_key_algorithm(pem) AS key_algorithm,
       list_filter([
         CASE WHEN x509.main.cert_is_expired(pem) THEN 'not currently valid' END,
         CASE WHEN timezone('UTC', not_after) BETWEEN now() AND now() + INTERVAL 30 DAY
              THEN 'expires within 30 days' END,
         CASE WHEN TRY_CAST(regexp_extract(key_algorithm, '^RSA-(\d+)$', 1) AS INTEGER) < 2048
              THEN 'RSA under 2048 bits' END,
         CASE WHEN regexp_matches(x509.main.cert_signature_algorithm(pem), 'SHA1|MD5')
              THEN 'SHA-1 or MD5 signature' END,
         CASE WHEN date_diff('day', x509.main.cert_not_before(pem), not_after) > 398
              THEN 'lifetime over 398 days' END,
         CASE WHEN x509.main.cert_issuer(pem) = x509.main.cert_subject(pem)
              THEN 'self-signed' END
       ], lambda f: f IS NOT NULL) AS findings
FROM my_certs
ORDER BY not_after;
```

398 days is the CA/Browser Forum maximum lifetime for a TLS server
certificate. `cert_not_after` returns a UTC `TIMESTAMP`, so `timezone('UTC', …)`
compares it with `now()` correctly in any session time zone.

To see which certificate serves each hostname you need, and whether it is still
valid:

```sql
WITH hosts(host) AS (VALUES ('www.example.com'), ('api.example.com'))
SELECT h.host, c.name AS covered_by, NOT x509.main.cert_is_expired(c.pem) AS valid_now
FROM hosts AS h
LEFT JOIN my_certs AS c ON list_contains(x509.main.cert_sans(c.pem), h.host)
ORDER BY h.host;
```

To find out which of your certificates a server is actually presenting, join
the live chain from `tls_inspect` to the inventory on the SHA-256 fingerprint
(a NULL `inventory_name` is a certificate you do not have on file):

```sql
SELECT t.seq, t.subject, t.not_after, c.name AS inventory_name
FROM x509.main.tls_inspect('example.com:443') AS t
LEFT JOIN my_certs AS c ON x509.main.cert_fingerprint(c.pem) = t.fingerprint
ORDER BY t.seq;
```

Runnable versions of these queries, over the worker's two committed sample
certificates, are in the schema's `vgi.example_queries` and on the examples of
`cert_not_after`, `cert_key_algorithm`, `cert_signature_algorithm`,
`cert_sans`, `cert_is_expired`, `tls_inspect`, `ct_search` and `ct_certificate`.

## Build & test

```sh
make build       # build the worker + mock-server (TLS + crt.sh) binaries
make test-unit   # pure-Go unit tests
make test-sql    # haybarn-unittest SQL E2E against a local mock TLS server
make test        # both
```

`test-sql` needs [`haybarn-unittest`](https://pypi.org/project/haybarn-unittest/)
on `PATH`:

```sh
uv tool install --prerelease allow 'haybarn-unittest>=2.0.0rc11,<2.1'
export PATH="$HOME/.local/bin:$PATH"
```

The cert-parsing scalars and `cert_info` are pure (no network) and are tested in
SQL against two committed PEM fixtures. `tls_inspect` is tested against a tiny mock
TLS server (`cmd/mockserver`) that presents a generated self-signed certificate;
the same process serves a mock of the crt.sh API (`internal/ctsample`) for
`ct_search` and `ct_certificate`, including its failure modes (HTTP 503 then
success, persistent 429, a non-JSON answer, a stall), so no test reaches the
real crt.sh. `make test-sql` runs `ci/run-integration.sh`, the same script CI
uses: it starts the mock server on free ports, points the tests at it via
`VGI_X509_TEST_ADDR` and `VGI_X509_CT_URL` (and at its certificate via
`VGI_X509_TEST_CERT_FILE`), and stops it afterward.
`make test-sql TRANSPORT=http` (or `unix`) runs the suite over another worker
transport.

The metadata gate is `vgi-lint`, configured by `vgi-lint.toml`:

```sh
make build
uvx --prerelease allow --from 'vgi-lint-check>=2.5.1' vgi-lint lint \
    --execute --execute-mode run --fail-on info
```

## Licensing

- This worker is licensed under the **MIT License** — see [`LICENSE`](./LICENSE).
- Certificate parsing and TLS inspection use only the **Go standard library**
  (`crypto/x509`, `encoding/pem`, `crypto/tls`) — no third-party crypto.
- Certificate Transparency search calls the public [crt.sh](https://crt.sh/)
  service (operated by Sectigo) over HTTPS; no account or API key.
- The VGI SDK [`vgi-go`](https://github.com/Query-farm/vgi-go) is a separate
  dependency under its own license (the Query Farm Source-Available License).

---

## Authorship & License

Written by [Query.Farm](https://query.farm).

Copyright 2026 Query Farm LLC - https://query.farm


## Notebooks

[Executed SQL walkthrough](notebooks/README.md): plan certificate work at a fixed UTC assessment time, visualize validity windows, and reconcile assignments with distinct fingerprints.
