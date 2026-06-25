// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"encoding/json"
	"strings"
)

// Shared per-object discovery / description metadata for the vgi-lint strict
// profile, which expects these tags on EVERY function and table:
//
//   - vgi.title     (VGI124) — human-friendly display name
//   - vgi.doc_llm   (VGI112) — Markdown narrative aimed at LLMs / agents
//   - vgi.doc_md    (VGI113) — Markdown narrative for human docs
//   - vgi.keywords  (VGI126/VGI138) — search terms / synonyms, encoded as a
//     JSON array of strings (e.g. ["a","b"]), NOT a comma-separated string.
//
// Per-object vgi.source_url is intentionally NOT emitted (VGI139): the
// source_url provenance lives only on the catalog object (WithCatalogInfo).
//
// objectTags(...) builds that map; extra per-object tags (e.g.
// vgi.result_columns_md, vgi.executable_examples) are added by the caller.

// KeywordsJSON encodes a comma-separated keyword list as a JSON array of
// strings (the form VGI138 requires for vgi.keywords). Surrounding whitespace
// is trimmed and empty entries are dropped. Exported so the catalog/schema
// keyword tags in cmd/ can reuse the same encoding.
func KeywordsJSON(csv string) string { return keywordsJSON(csv) }

// keywordsJSON encodes a comma-separated keyword list as a JSON array of
// strings (the form VGI138 requires for vgi.keywords). Surrounding whitespace
// is trimmed and empty entries are dropped.
func keywordsJSON(csv string) string {
	parts := strings.Split(csv, ",")
	kw := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			kw = append(kw, s)
		}
	}
	return mustJSON(kw)
}

// objectTags builds the standard per-object discovery/description tags. The
// keywords argument is a comma-separated list; it is encoded as a JSON array
// for the vgi.keywords tag (VGI138).
func objectTags(title, docLLM, docMD, keywords string) map[string]string {
	return map[string]string{
		"vgi.title":    title,
		"vgi.doc_llm":  docLLM,
		"vgi.doc_md":   docMD,
		"vgi.keywords": keywordsJSON(keywords),
	}
}

// merge returns a new map combining base with extra (extra wins on conflict).
func merge(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// fixturePEM is a committed, self-signed X.509 certificate used as the input for
// every guaranteed-runnable example query (VGI506 / VGI509) and the illustrative
// per-function examples (VGI901/902). It is the same fixture asserted by
// test/sql/cert_offline.test: CN=test.vgi-x509.example, valid 2025-01-01 ..
// 2035-01-01, ECDSA P-256, SANs test.vgi-x509.example / alt.vgi-x509.example /
// 127.0.0.1. Using a real certificate (instead of a "...") makes the examples
// EXECUTE cleanly when the linter runs them against the attached worker.
const fixturePEM = "-----BEGIN CERTIFICATE-----\n" +
	"MIIB3DCCAYGgAwIBAgIEOt5osTAKBggqhkjOPQQDAjA7MRkwFwYDVQQKExBWR0kg\n" +
	"WDUwOSBGaXh0dXJlMR4wHAYDVQQDExV0ZXN0LnZnaS14NTA5LmV4YW1wbGUwHhcN\n" +
	"MjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA7MRkwFwYDVQQKExBWR0kgWDUw\n" +
	"OSBGaXh0dXJlMR4wHAYDVQQDExV0ZXN0LnZnaS14NTA5LmV4YW1wbGUwWTATBgcq\n" +
	"hkjOPQIBBggqhkjOPQMBBwNCAAS7Zbq+Bz73Y0wKrZZkw4owgz7qyAtXYUrNUkac\n" +
	"Ot2h1WpF/Y+ODgRoeo0+ixbqPxA8+Lm9DTpksjsxTMRni/Owo3MwcTAOBgNVHQ8B\n" +
	"Af8EBAMCAoQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADA8BgNV\n" +
	"HREENTAzghV0ZXN0LnZnaS14NTA5LmV4YW1wbGWCFGFsdC52Z2kteDUwOS5leGFt\n" +
	"cGxlhwR/AAABMAoGCCqGSM49BAMCA0kAMEYCIQCGCty4v7uWVHE/HhanzxE2kzBo\n" +
	"KBiJ1j25vqPbFP4x7AIhAPdzfBNzgiIxriWsiBH1HBtoOCRsMJ6WN+j7zxyn9Np0\n" +
	"-----END CERTIFICATE-----"

// executableExample is one guaranteed-runnable example (VGI509). expected_result
// is intentionally omitted — the linter only needs each query to execute cleanly.
type executableExample struct {
	Description string `json:"description"`
	SQL         string `json:"sql"`
}

// executableExamplesJSON is the JSON-encoded vgi.executable_examples payload: a
// list of {"description","sql"} objects whose SQL is catalog-qualified
// (x509.main.<fn>(...)) and self-contained (it embeds the fixture PEM), so every
// statement runs as written against the attached worker. Only OFFLINE functions
// are used here (tls_inspect needs a live network endpoint and is excluded).
var executableExamplesJSON = mustJSON([]executableExample{
	{
		Description: "Read the subject distinguished name of a certificate.",
		SQL:         "SELECT x509.main.cert_subject('" + fixturePEM + "') AS subject",
	},
	{
		Description: "Read the issuer distinguished name of a certificate.",
		SQL:         "SELECT x509.main.cert_issuer('" + fixturePEM + "') AS issuer",
	},
	{
		Description: "Read the public-key algorithm and size/curve.",
		SQL:         "SELECT x509.main.cert_key_algorithm('" + fixturePEM + "') AS key_algorithm",
	},
	{
		Description: "Compute the SHA-256 fingerprint (lowercase hex).",
		SQL:         "SELECT x509.main.cert_fingerprint('" + fixturePEM + "') AS fingerprint",
	},
	{
		Description: "Check whether the certificate is a CA certificate.",
		SQL:         "SELECT x509.main.cert_is_ca('" + fixturePEM + "') AS is_ca",
	},
	{
		Description: "Check whether the certificate is currently expired.",
		SQL:         "SELECT x509.main.cert_is_expired('" + fixturePEM + "') AS is_expired",
	},
	{
		Description: "Read the start of the certificate validity window (UTC).",
		SQL:         "SELECT x509.main.cert_not_before('" + fixturePEM + "') AS not_before",
	},
	{
		Description: "Read the certificate expiry (end of validity window, UTC).",
		SQL:         "SELECT x509.main.cert_not_after('" + fixturePEM + "') AS not_after",
	},
	{
		Description: "List the subject alternative names (DNS names then IP addresses).",
		SQL:         "SELECT x509.main.cert_sans('" + fixturePEM + "') AS sans",
	},
	{
		Description: "Dump every certificate attribute as (field, value) rows.",
		SQL:         "SELECT field, value FROM x509.main.cert_info('" + fixturePEM + "') ORDER BY field",
	},
})

// SchemaExampleQueries is the schema-level vgi.example_queries payload (VGI506):
// a plain string of representative, catalog-qualified SQL. It uses only OFFLINE
// functions over the committed fixture PEM so every line executes as written when
// the worker is attached (tls_inspect needs a live network endpoint, so it is
// shown only as an illustrative comment, not an executable statement).
var SchemaExampleQueries = "SELECT x509.main.cert_subject('" + fixturePEM + "');\n" +
	"SELECT x509.main.cert_issuer('" + fixturePEM + "');\n" +
	"SELECT x509.main.cert_fingerprint('" + fixturePEM + "');\n" +
	"SELECT x509.main.cert_is_expired('" + fixturePEM + "');\n" +
	"SELECT x509.main.cert_sans('" + fixturePEM + "');\n" +
	"SELECT field, value FROM x509.main.cert_info('" + fixturePEM + "') ORDER BY field;"

// mustJSON marshals v to a compact JSON string, panicking on failure (the inputs
// are static, so a failure is a programming error caught at startup).
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
