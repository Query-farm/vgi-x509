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

// scalarExecExampleJSON builds a one-entry vgi.executable_examples payload for a
// scalar that takes a single certificate argument. It embeds the committed
// fixture PEM so the query runs as written (VGI509) and shows an agent the exact
// canonical call for that function, which is what `vgi-lint simulate` needs to
// converge on the reference solution (VGI920).
func scalarExecExampleJSON(fn, desc string) string {
	return mustJSON([]executableExample{{
		Description: desc,
		SQL:         "SELECT x509.main." + fn + "('" + fixturePEM + "') AS " + fn,
	}})
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

// Category names (VGI413): the schema declares a vgi.categories registry
// (CategoriesJSON) and every object tags itself with a vgi.category naming one of
// these entries. Categories drive the worker's navigation and listing sections.
const (
	// CategoryParsing groups the offline certificate functions (scalars + cert_info).
	CategoryParsing = "Certificate parsing"
	// CategoryTLS groups the live TLS-endpoint inspection (tls_inspect).
	CategoryTLS = "TLS endpoints"
)

// category is one {name, description} entry in the vgi.categories registry.
type category struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CategoriesJSON is the schema-level vgi.categories payload (VGI413): an ordered
// JSON array of {name, description} objects. Each function/table tags itself with
// a vgi.category naming one of these. Exported so the schema tags in cmd/ can
// attach it.
var CategoriesJSON = mustJSON([]category{
	{
		Name: CategoryParsing,
		Description: "Parse a single X.509 certificate — supplied as PEM text or DER bytes — offline and read " +
			"its fields: subject, issuer, serial, public-key and signature algorithms, SHA-256 fingerprint, " +
			"validity window, CA flag, and subject alternative names, or dump every attribute as rows.",
	},
	{
		Name: CategoryTLS,
		Description: "Connect to a live TLS endpoint given as host:port (AUTHORIZED endpoints only) and return " +
			"the certificate chain the server presents.",
	},
})

// agentTestTask is one analyst task for `vgi-lint simulate` (VGI152 / VGI920):
// a natural-language prompt and the reference SQL that answers it.
type agentTestTask struct {
	Name         string `json:"name"`
	Prompt       string `json:"prompt"`
	ReferenceSQL string `json:"reference_sql,omitempty"`
}

// AgentTestTasksJSON is the catalog-level vgi.agent_test_tasks payload (VGI152):
// a JSON array of {name, prompt, reference_sql} tasks that `vgi-lint simulate`
// uses to measure how well an agent actually drives this worker. Every task is
// OFFLINE — each prompt embeds the committed fixture certificate so the agent can
// answer with the offline cert-parsing functions, with no live TLS endpoint
// needed to run the reference SQL. Exported so the catalog tags in cmd/ can
// attach it.
var AgentTestTasksJSON = mustJSON([]agentTestTask{
	{
		Name:         "certificate serial number",
		Prompt:       "Return the serial number of this X.509 certificate as a single value, exactly as the worker reports it:\n" + fixturePEM,
		ReferenceSQL: "SELECT x509.main.cert_serial('" + fixturePEM + "') AS serial",
	},
	{
		Name:         "public-key algorithm",
		Prompt:       "What public-key algorithm and size/curve does this certificate use? Return the single value the worker reports:\n" + fixturePEM,
		ReferenceSQL: "SELECT x509.main.cert_key_algorithm('" + fixturePEM + "') AS key_algorithm",
	},
	{
		Name:         "signature algorithm",
		Prompt:       "What algorithm was used to sign this certificate? Return the single value the worker reports:\n" + fixturePEM,
		ReferenceSQL: "SELECT x509.main.cert_signature_algorithm('" + fixturePEM + "') AS signature_algorithm",
	},
	{
		Name:         "certificate fingerprint",
		Prompt:       "Compute the SHA-256 fingerprint of this certificate as lowercase hex:\n" + fixturePEM,
		ReferenceSQL: "SELECT x509.main.cert_fingerprint('" + fixturePEM + "') AS fingerprint",
	},
	{
		Name:         "is a CA certificate",
		Prompt:       "Is this certificate a certificate-authority (CA) certificate? Return a boolean:\n" + fixturePEM,
		ReferenceSQL: "SELECT x509.main.cert_is_ca('" + fixturePEM + "') AS is_ca",
	},
	{
		Name:         "certificate expiry check",
		Prompt:       "Is this certificate currently expired (outside its validity window)? Return a boolean:\n" + fixturePEM,
		ReferenceSQL: "SELECT x509.main.cert_is_expired('" + fixturePEM + "') AS is_expired",
	},
	{
		Name:         "certificate expiry timestamp",
		Prompt:       "When does this certificate expire? Return the end of its validity window as a timestamp:\n" + fixturePEM,
		ReferenceSQL: "SELECT x509.main.cert_not_after('" + fixturePEM + "') AS not_after",
	},
	{
		Name:         "certificate subject",
		Prompt:       "Return the subject distinguished name of this X.509 certificate exactly as the worker reports it (do not reorder or reformat the string):\n" + fixturePEM,
		ReferenceSQL: "SELECT x509.main.cert_subject('" + fixturePEM + "') AS subject",
	},
	{
		Name:         "certificate issuer",
		Prompt:       "Which certificate authority issued this certificate? Return the issuer distinguished name exactly as the worker reports it (do not reorder or reformat the string):\n" + fixturePEM,
		ReferenceSQL: "SELECT x509.main.cert_issuer('" + fixturePEM + "') AS issuer",
	},
	{
		Name:         "subject alternative names",
		Prompt:       "Return the subject alternative names (DNS names and IP addresses) of this certificate as the single list value the worker reports:\n" + fixturePEM,
		ReferenceSQL: "SELECT x509.main.cert_sans('" + fixturePEM + "') AS sans",
	},
	{
		Name:         "dump all certificate fields",
		Prompt:       "Dump every attribute of this certificate as (field, value) rows, ordered by field:\n" + fixturePEM,
		ReferenceSQL: "SELECT field, value FROM x509.main.cert_info('" + fixturePEM + "') ORDER BY field",
	},
})

// mustJSON marshals v to a compact JSON string, panicking on failure (the inputs
// are static, so a failure is a programming error caught at startup).
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
