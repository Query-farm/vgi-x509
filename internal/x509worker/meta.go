// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"encoding/json"
	"strings"

	"github.com/Query-farm/vgi-go/vgi"
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

// SchemaExampleQueries is the schema-level vgi.example_queries payload (VGI506 /
// VGI515): a JSON array of {description, sql} objects — every example carries a
// human-readable description (the plain-string form the native carrier keeps
// drops descriptions). It uses only OFFLINE functions over the committed fixture
// PEM so every statement executes as written when the worker is attached
// (tls_inspect needs a live network endpoint and is excluded). Each example
// embeds the ~800-character fixture, so the list stays at four to keep the tag
// under the 4,000-character agent context limit (VGI417); every function also
// carries its own examples.
var SchemaExampleQueries = mustJSON([]executableExample{
	{
		Description: "Read the subject distinguished name of a certificate.",
		SQL:         "SELECT x509.main.cert_subject('" + fixturePEM + "') AS subject",
	},
	{
		Description: "Flag a certificate that is currently outside its validity window.",
		SQL:         "SELECT x509.main.cert_is_expired('" + fixturePEM + "') AS is_expired",
	},
	{
		Description: "List a certificate's subject alternative names (DNS names then IP addresses).",
		SQL:         "SELECT x509.main.cert_sans('" + fixturePEM + "') AS sans",
	},
	{
		Description: "Dump every certificate attribute as (field, value) rows, ordered by field.",
		SQL:         "SELECT field, value FROM x509.main.cert_info('" + fixturePEM + "') ORDER BY field",
	},
})

// exampleQueriesJSON encodes a function's CatalogExample list as the
// vgi.example_queries tag payload (VGI515): a JSON array of {description, sql}
// objects. Emitting it as a tag preserves each example's description, which the
// native duckdb_functions().examples carrier drops.
func exampleQueriesJSON(exs []vgi.CatalogExample) string {
	out := make([]executableExample, len(exs))
	for i, e := range exs {
		out[i] = executableExample{Description: e.Description, SQL: e.SQL}
	}
	return mustJSON(out)
}

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

// agentTestTask is one analyst task for `vgi-lint simulate` (VGI152 / VGI920): a
// natural-language prompt. Only name + prompt are published (VGI416); each task's
// grader-only oracle lives in the private repo-root sidecar vgi-agent-tests.yaml,
// keyed by task name, which vgi-lint discovers on its own. Deterministic, offline
// tasks use reference_sql (exact result compare, with ignore_column_names). Live
// tasks (tls_inspect, whose output is a real server certificate that rotates)
// instead use check_sql — a post-session boolean assertion of a STABLE fact — so
// grading cannot flake on cert rotation. Keep the sidecar in sync when a task
// changes.
type agentTestTask struct {
	Name   string `json:"name"`
	Prompt string `json:"prompt"`
}

// AgentTestTasksJSON is the catalog-level vgi.agent_test_tasks payload (VGI152):
// a JSON array of {name, prompt} tasks that `vgi-lint simulate`
// uses to measure how well an agent actually drives this worker. Every task is
// OFFLINE — each prompt embeds the committed fixture certificate so the agent can
// answer with the offline cert-parsing functions, with no live TLS endpoint
// needed to run the reference SQL. Exported so the catalog tags in cmd/ can
// attach it.
var AgentTestTasksJSON = mustJSON([]agentTestTask{
	{
		Name:   "certificate serial number",
		Prompt: "Return the serial number of this X.509 certificate as a single value, exactly as the worker reports it:\n" + fixturePEM,
	},
	{
		// Reframed as a yes/no predicate over the worker's own output so grading
		// cannot flake on how the analyst spells or aliases the algorithm string
		// (e.g. "ECDSA" vs "ECDSA-P256" vs a renamed column). The fixture key is
		// ECDSA on NIST P-256, so cert_key_algorithm returns exactly 'ECDSA-P256'.
		Name:   "public-key algorithm is ECDSA P-256",
		Prompt: "Does this certificate use an ECDSA key on the NIST P-256 curve? Return a single boolean.\n" + fixturePEM,
	},
	{
		Name:   "signature algorithm",
		Prompt: "What algorithm was used to sign this certificate? Return the single value the worker reports:\n" + fixturePEM,
	},
	{
		Name:   "certificate fingerprint",
		Prompt: "Compute the SHA-256 fingerprint of this certificate as lowercase hex:\n" + fixturePEM,
	},
	{
		Name:   "is a CA certificate",
		Prompt: "Is this certificate a certificate-authority (CA) certificate? Return a boolean:\n" + fixturePEM,
	},
	{
		Name:   "certificate expiry check",
		Prompt: "Is this certificate currently expired (outside its validity window)? Return a boolean:\n" + fixturePEM,
	},
	{
		Name:   "certificate expiry timestamp",
		Prompt: "When does this certificate expire? Return the end of its validity window as a timestamp:\n" + fixturePEM,
	},
	{
		Name:   "certificate valid-from timestamp",
		Prompt: "When does this certificate become valid? Return the start of its validity window (notBefore) as a single timestamp:\n" + fixturePEM,
	},
	{
		Name: "boolean-valued certificate fields",
		Prompt: "This worker exposes a browsable registry of every certificate attribute it can read and the scalar function that returns each one. " +
			"Using that registry, list the fields whose result type is BOOLEAN together with the scalar function that returns them, ordered by field name.",
	},
	{
		// tls_inspect connects to a LIVE endpoint whose certificate rotates, so an
		// exact reference compare would be a latent flake. Grade instead via a
		// check_sql assertion of a stable fact: the leaf certificate (seq 0) a TLS
		// server presents is never itself a CA certificate. example.com is an
		// IANA-operated, long-stable endpoint used only for this defensive probe.
		Name: "live TLS endpoint leaf certificate",
		Prompt: "Connect to the live TLS endpoint example.com:443 and inspect the certificate chain it presents. " +
			"Is the leaf certificate — the one at sequence 0 — itself a certificate-authority (CA) certificate? Return a single boolean.",
	},
	{
		// Reframed as a yes/no predicate over the worker's own cert_subject output:
		// asking the analyst to reproduce a distinguished-name string verbatim is a
		// latent flake because an agent reorders or reformats the RDN components. The
		// fixture subject is CN=test.vgi-x509.example,O=VGI X509 Fixture, so its
		// distinguished name contains the host name test.vgi-x509.example.
		Name:   "certificate subject names the expected host",
		Prompt: "Does the subject of this certificate name the host test.vgi-x509.example (i.e. its subject distinguished name contains that name)? Return a single boolean.\n" + fixturePEM,
	},
	{
		// Reframed as a boolean self-issued check for the same reason as the subject
		// task. The fixture is self-signed, so its issuer distinguished name equals
		// its subject distinguished name.
		Name:   "certificate is self-issued",
		Prompt: "Is this certificate self-issued — that is, does its issuer distinguished name equal its subject distinguished name? Return a single boolean.\n" + fixturePEM,
	},
	{
		// Reframed as a set-membership predicate: returning a whole list value verbatim
		// is a latent flake (the analyst may unnest it to rows or reorder it). The
		// fixture's subject alternative names include the DNS name alt.vgi-x509.example.
		Name:   "subject alternative names include alt host",
		Prompt: "Is alt.vgi-x509.example one of this certificate's subject alternative names (SANs)? Return a single boolean.\n" + fixturePEM,
	},
	{
		Name:   "dump all certificate fields",
		Prompt: "Dump every attribute of this certificate as (field, value) rows, ordered by field:\n" + fixturePEM,
	},
})

// resultColumn is one {name, type, description} entry in a table function's
// vgi.result_columns_schema (VGI307): the structured, machine-readable declaration
// of a static result column. It replaces the retired free-text vgi.result_columns_md
// (VGI414 / VGI405).
type resultColumn struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// resultColumnsSchemaJSON encodes the given columns as the vgi.result_columns_schema
// tag payload: a JSON array of {name, type, description} objects, one per column.
func resultColumnsSchemaJSON(cols ...resultColumn) string { return mustJSON(cols) }

// ---------------------------------------------------------------------------
// cert_fields browsable registry (VGI146).
//
// A worker with only table functions and no browsable table/view forces an agent
// to guess arguments before it can see any data. The cert_fields VIEW is a
// curated, VALUES-backed registry (no network, no credential — so it also clears
// the VGI911 scan probe for free) that maps every attribute cert_info emits to the
// scalar function that returns it and that value's DuckDB type. Browsing it teaches
// an agent the worker's whole certificate surface without parsing a cert first.
// ---------------------------------------------------------------------------

// certField is one row of the cert_fields registry.
type certField struct {
	Field      string // attribute name, matching internal/x509worker/info.go CertInfo
	Scalar     string // the scalar function that returns this field individually
	ResultType string // DuckDB type of that scalar's result
	Desc       string // human description
}

// certFieldRegistry is the ordered attribute set, kept in lockstep with CertInfo
// (info.go) and the scalars registered in functions.go Register — so the browsable
// view and the cert_info dump cannot drift.
var certFieldRegistry = []certField{
	{"subject", "cert_subject", "VARCHAR", "Subject distinguished name (RFC 2253)."},
	{"issuer", "cert_issuer", "VARCHAR", "Issuer distinguished name of the signing CA (RFC 2253)."},
	{"serial", "cert_serial", "VARCHAR", "Serial number as a decimal string."},
	{"not_before", "cert_not_before", "TIMESTAMP", "Start of the validity window (UTC)."},
	{"not_after", "cert_not_after", "TIMESTAMP", "End of the validity window / expiry (UTC)."},
	{"is_expired", "cert_is_expired", "BOOLEAN", "Whether the certificate is outside its validity window right now."},
	{"key_algorithm", "cert_key_algorithm", "VARCHAR", "Public-key algorithm with size or curve (e.g. RSA-2048, ECDSA-P256)."},
	{"signature_algorithm", "cert_signature_algorithm", "VARCHAR", "Algorithm used to sign the certificate (e.g. ECDSA-SHA256)."},
	{"fingerprint_sha256", "cert_fingerprint", "VARCHAR", "SHA-256 fingerprint of the DER encoding (lowercase hex)."},
	{"is_ca", "cert_is_ca", "BOOLEAN", "Whether the certificate is a certificate-authority (CA) certificate."},
	{"sans", "cert_sans", "VARCHAR[]", "Subject alternative names: DNS names then IP addresses."},
}

// CertFieldsViewName is the name of the browsable certificate-field registry view.
const CertFieldsViewName = "cert_fields"

// sqlStr renders s as a single-quoted SQL string literal (doubling embedded quotes).
func sqlStr(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// CertFieldsViewDefinition builds the SQL backing the cert_fields view: a
// VALUES-backed scan (credential-free, no network). Columns: field,
// scalar_function, result_type, description.
func CertFieldsViewDefinition() string {
	var b strings.Builder
	b.WriteString("SELECT * FROM (VALUES ")
	for i, f := range certFieldRegistry {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("(" + sqlStr(f.Field) + ", " + sqlStr(f.Scalar) + ", " + sqlStr(f.ResultType) + ", " + sqlStr(f.Desc) + ")")
	}
	b.WriteString(") AS t(field, scalar_function, result_type, description)")
	return b.String()
}

// mustJSON marshals v to a compact JSON string, panicking on failure (the inputs
// are static, so a failure is a programming error caught at startup).
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
