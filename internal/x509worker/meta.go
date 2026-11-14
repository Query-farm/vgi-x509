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

// legacyPEM is a second committed fixture, so composed examples and agent tasks
// can audit an inventory of more than one certificate. It is deliberately the
// opposite of fixturePEM on every policy axis: CN=legacy.vgi-x509.example,
// serial 1001, valid 2015-01-01 .. 2016-01-01 (expired, 365-day lifetime), an
// RSA-1024 key (weak), signed with ECDSA-SHA1 (deprecated) by a separate
// "VGI X509 Fixture CA" (so not self-signed), SAN legacy.vgi-x509.example. The
// CA's key was thrown away; nothing here verifies the signature.
const legacyPEM = "-----BEGIN CERTIFICATE-----\n" +
	"MIIB0jCCAXigAwIBAgICA+kwCQYHKoZIzj0EATA5MRkwFwYDVQQKExBWR0kgWDUw\n" +
	"OSBGaXh0dXJlMRwwGgYDVQQDExNWR0kgWDUwOSBGaXh0dXJlIENBMB4XDTE1MDEw\n" +
	"MTAwMDAwMFoXDTE2MDEwMTAwMDAwMFowPTEZMBcGA1UEChMQVkdJIFg1MDkgRml4\n" +
	"dHVyZTEgMB4GA1UEAxMXbGVnYWN5LnZnaS14NTA5LmV4YW1wbGUwgZ8wDQYJKoZI\n" +
	"hvcNAQEBBQADgY0AMIGJAoGBAKnXtIZR7d7y/tykoXIu2UFuu6pOM3wTOgeA9REt\n" +
	"a9h+tGfssuxWZ7c8ILquhCxda+A92qlCepAbgh7sfDCoV7X0ST5gzF+YuzXRxgxh\n" +
	"drwhmeFLO9QcuVLF/Xu6japDPQ/eC6E/gaA0+p8vhE98WWC45S34wUPbPjmIEMC0\n" +
	"lr9JAgMBAAGjJjAkMCIGA1UdEQQbMBmCF2xlZ2FjeS52Z2kteDUwOS5leGFtcGxl\n" +
	"MAkGByqGSM49BAEDSQAwRgIhAKsIPC+paKp/9ZycM4y3pUVIFfHc0Kl7OsEuceKa\n" +
	"riO1AiEA1Cd3nEmbffFOBMjt3TmYKYZRo4DskxRqX4I41HUb274=\n" +
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
// PEMs so every statement executes as written when the worker is attached
// (tls_inspect needs a live network endpoint, so its composed example lives only
// on tls_inspect). Each example embeds at least one ~800-character fixture, so
// the list is sized against the 8,000-character limit vgi-lint applies to
// example lists (VGI417); TestExampleListsWithinAgentLimit guards it.
//
// The composed examples (several of the worker's objects in one query) also sit
// on the function that drives each query, because the vgi-lint agent simulator
// only shows agents per-object examples (describe_function), never this list.
var SchemaExampleQueries = exampleQueriesJSON([]vgi.CatalogExample{
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
	ComposedPolicyAuditExample,
	ComposedHostCoverageExample,
})

// Composed examples: each one combines several of this worker's objects in one
// query, which is how the functions are used in practice (a certificate review
// rarely asks for a single field). Each SQL is defined once here and referenced
// from the schema list and from the driving object's example list.

// inventoryCTE defines certs(name, pem), a two-certificate inventory over both
// committed fixtures: the stand-in for a real table of PEM or DER certificates.
const inventoryCTE = "WITH certs(name, pem) AS (VALUES ('test', '" + fixturePEM + "'), " +
	"('legacy', '" + legacyPEM + "'))"

// ComposedPolicyAuditExample is a certificate compliance report: one row per
// certificate with its policy findings (outside the validity window, expiring
// within 30 days, RSA under 2048 bits, SHA-1/MD5 signature, lifetime over the
// CA/Browser Forum 398-day limit, self-signed). Driven by cert_not_after,
// cert_key_algorithm and cert_signature_algorithm.
var ComposedPolicyAuditExample = vgi.CatalogExample{
	Description: "Compliance audit of a certificate inventory: expiry, key algorithm and policy findings " +
		"per certificate. The legacy sample is expired, RSA-1024 and SHA-1 signed; the test sample is self-signed " +
		"with a 10-year lifetime.",
	SQL: inventoryCTE + " SELECT name, x509.main.cert_not_after(pem) AS not_after, " +
		"x509.main.cert_key_algorithm(pem) AS key_algorithm, list_filter([" +
		"CASE WHEN x509.main.cert_is_expired(pem) THEN 'not currently valid' END, " +
		"CASE WHEN timezone('UTC', not_after) BETWEEN now() AND now() + INTERVAL 30 DAY THEN 'expires within 30 days' END, " +
		"CASE WHEN TRY_CAST(regexp_extract(key_algorithm, '^RSA-(\\d+)$', 1) AS INTEGER) < 2048 THEN 'RSA under 2048 bits' END, " +
		"CASE WHEN regexp_matches(x509.main.cert_signature_algorithm(pem), 'SHA1|MD5') THEN 'SHA-1 or MD5 signature' END, " +
		"CASE WHEN date_diff('day', x509.main.cert_not_before(pem), not_after) > 398 THEN 'lifetime over 398 days' END, " +
		"CASE WHEN x509.main.cert_issuer(pem) = x509.main.cert_subject(pem) THEN 'self-signed' END" +
		"], lambda f: f IS NOT NULL) AS findings FROM certs ORDER BY not_after",
}

// ComposedHostCoverageExample answers the deploy-time question "which of my
// certificates serves each required hostname, and is it valid right now?".
// Driven by cert_sans (with cert_is_expired).
var ComposedHostCoverageExample = vgi.CatalogExample{
	Description: "Hostname coverage: for each required hostname, the inventory certificate whose SANs list it and " +
		"whether it is valid now. Here alt is covered by a valid certificate, legacy only by an expired one, " +
		"www by none (NULL).",
	SQL: inventoryCTE + ", hosts(host) AS (VALUES ('alt.vgi-x509.example'), ('legacy.vgi-x509.example'), " +
		"('www.vgi-x509.example')) " +
		"SELECT r.host, i.name AS covered_by, NOT x509.main.cert_is_expired(i.pem) AS valid_now " +
		"FROM hosts AS r LEFT JOIN certs AS i ON list_contains(x509.main.cert_sans(i.pem), r.host) " +
		"ORDER BY r.host",
}

// ComposedLiveInventoryExample maps the chain a live server presents onto a
// certificate inventory by SHA-256 fingerprint (tls_inspect + cert_fingerprint):
// the useful form of certificate pinning, since it says WHICH inventory
// certificate is deployed. Live network, so it sits only on tls_inspect.
var ComposedLiveInventoryExample = vgi.CatalogExample{
	Description: "Which inventory certificate a server is serving (AUTHORIZED endpoints only): join each certificate " +
		"in the presented chain (tls_inspect) to an inventory on cert_fingerprint. inventory_name is NULL for a " +
		"certificate that is not in the inventory, which is every row for example.com against the two samples.",
	SQL: inventoryCTE + " SELECT t.seq, t.subject, t.not_after, i.name AS inventory_name " +
		"FROM x509.main.tls_inspect('example.com:443') AS t " +
		"LEFT JOIN certs AS i ON x509.main.cert_fingerprint(i.pem) = t.fingerprint ORDER BY t.seq",
}

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
// keyed by task name, which vgi-lint discovers on its own. Offline tasks use
// reference_sql (exact result compare, with ignore_column_names), so every such
// prompt pins the shape of the answer: row count, column count and type. The one
// live task (tls_inspect, whose certificate rotates) has the analyst record its
// answer in a temp table and grades it with check_sql against a fresh
// tls_inspect call, so a wrong answer fails. Keep the sidecar in sync when a task
// changes; TestAgentTasksMatchSidecar guards the names.
type agentTestTask struct {
	Name   string `json:"name"`
	Prompt string `json:"prompt"`
}

// twoCertPrompt appends both committed fixtures, labelled A and B.
func twoCertPrompt(question string) string {
	return question + "\nCertificate A:\n" + fixturePEM + "\nCertificate B:\n" + legacyPEM
}

// AgentTestTasksJSON is the catalog-level vgi.agent_test_tasks payload (VGI152):
// a JSON array of {name, prompt} tasks that `vgi-lint simulate` uses to measure
// how well an agent actually drives this worker. All but one are offline: each
// prompt embeds a committed fixture certificate. Exported so the catalog tags in
// cmd/ can attach it.
var AgentTestTasksJSON = mustJSON([]agentTestTask{
	{
		Name: "certificate serial number",
		Prompt: "What is the serial number of this X.509 certificate? Return one row with one VARCHAR column: " +
			"the serial number as a decimal string, exactly as the worker reports it.\n" + fixturePEM,
	},
	{
		// A yes/no predicate over the worker's own output, so grading cannot flake
		// on how the analyst spells the algorithm. cert_key_algorithm returns
		// exactly 'ECDSA-P256' for the fixture.
		Name:   "public-key algorithm is ECDSA P-256",
		Prompt: "Does this certificate use an ECDSA key on the NIST P-256 curve? Return one row with one BOOLEAN column.\n" + fixturePEM,
	},
	{
		Name: "signature algorithm",
		Prompt: "What algorithm was used to sign this certificate? Return one row with one VARCHAR column: the " +
			"algorithm name exactly as the worker reports it.\n" + fixturePEM,
	},
	{
		Name: "certificate fingerprint",
		Prompt: "Compute the SHA-256 fingerprint of this certificate. Return one row with one VARCHAR column: " +
			"the fingerprint as lowercase hex with no separators.\n" + fixturePEM,
	},
	{
		Name:   "is a CA certificate",
		Prompt: "Is this certificate a certificate-authority (CA) certificate? Return one row with one BOOLEAN column.\n" + fixturePEM,
	},
	{
		// The legacy fixture expired in 2016, so the answer is true: an agent
		// that guesses "not expired" fails.
		Name: "certificate expiry check",
		Prompt: "Is this certificate currently expired (outside its validity window)? Return one row with one " +
			"BOOLEAN column.\n" + legacyPEM,
	},
	{
		Name: "certificate expiry timestamp",
		Prompt: "When does this certificate expire? Return one row with one TIMESTAMP column (UTC): the end of " +
			"its validity window (notAfter).\n" + fixturePEM,
	},
	{
		Name: "certificate valid-from timestamp",
		Prompt: "When does this certificate become valid? Return one row with one TIMESTAMP column (UTC): the " +
			"start of its validity window (notBefore).\n" + fixturePEM,
	},
	{
		// An aggregate over the cert_fields registry, so the answer is not the
		// view's published filter example with a different literal.
		Name: "scalar function count by result type",
		Prompt: "This worker exposes a browsable registry of every certificate attribute it can read, the scalar " +
			"function that returns each one, and that function's result type. Using that registry, count the " +
			"scalar functions per result type. Return one row per result type with two columns: the type name " +
			"(VARCHAR) and the number of functions (BIGINT), ordered by type name.",
	},
	{
		// Graded by check_sql (see vgi-agent-tests.yaml): it re-inspects the live
		// endpoint and compares with the analyst's temp table, so the grade
		// tracks certificate rotation and still fails a wrong answer.
		// example.com is an IANA-operated, long-stable endpoint used only for
		// this defensive probe.
		Name: "live TLS endpoint chain",
		Prompt: "Connect to the live TLS endpoint example.com:443 and inspect the certificate chain it presents. " +
			"Record your answer in a temporary table named answer with exactly one row and two columns: " +
			"chain_length INTEGER (how many certificates the server presented) and leaf_is_ca BOOLEAN (whether " +
			"the leaf certificate, sequence 0, is itself a certificate-authority certificate).",
	},
	{
		// A predicate rather than the DN string: an agent may reorder or reformat
		// RDN components. The fixture subject is
		// CN=test.vgi-x509.example,O=VGI X509 Fixture.
		Name: "certificate subject names the expected host",
		Prompt: "Does the subject distinguished name of this certificate contain the host name test.vgi-x509.example? " +
			"Return one row with one BOOLEAN column.\n" + fixturePEM,
	},
	{
		// The fixture is self-signed, so its issuer DN equals its subject DN.
		Name: "certificate is self-issued",
		Prompt: "Is this certificate self-issued, that is, does its issuer distinguished name equal its subject " +
			"distinguished name? Return one row with one BOOLEAN column.\n" + fixturePEM,
	},
	{
		// Set membership rather than the whole list, which an agent may unnest.
		Name: "subject alternative names include alt host",
		Prompt: "Is alt.vgi-x509.example one of this certificate's subject alternative names (SANs)? Return one " +
			"row with one BOOLEAN column.\n" + fixturePEM,
	},
	{
		// Composed: cert_info over two certificates, joined on field. The only
		// attribute the two fixtures share is is_ca (false).
		Name: "attributes shared by two certificates",
		Prompt: twoCertPrompt("Compare these two certificates attribute by attribute using the worker's " +
			"long-format certificate dump. Which attributes have the same value in both? Return one VARCHAR " +
			"column with the attribute names exactly as the dump names them, one row per attribute, ordered by name."),
	},
	{
		// Composed: cert_not_before + cert_not_after + cert_fingerprint. Only
		// certificate A (10-year lifetime) exceeds 398 days.
		Name: "certificate lifetime over 398 days",
		Prompt: twoCertPrompt("Which of these two certificates has a validity period (notBefore to notAfter) " +
			"longer than 398 days, the CA/Browser Forum maximum for TLS server certificates? Return one row with " +
			"one VARCHAR column: that certificate's SHA-256 fingerprint as lowercase hex."),
	},
	{
		// Composed: cert_key_algorithm + cert_signature_algorithm + cert_serial.
		// Only certificate B (RSA-1024, ECDSA-SHA1) is weak; its serial is 1001.
		Name: "certificate with weak cryptography",
		Prompt: twoCertPrompt("Which of these two certificates has weak cryptography: an RSA key shorter than " +
			"2048 bits, or a SHA-1 or MD5 signature? Return one row with one VARCHAR column: its serial number " +
			"as a decimal string, exactly as the worker reports it."),
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
