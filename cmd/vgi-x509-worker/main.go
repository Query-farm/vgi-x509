// Copyright 2026 Query Farm LLC - https://query.farm

// Command vgi-x509-worker is a VGI worker that parses X.509 certificates and
// inspects TLS endpoints, exposed as DuckDB SQL functions. It is a defensive
// security / compliance tool. It speaks the VGI protocol over stdio.
package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-x509/internal/x509worker"
)

func main() {
	// Accept --http for HTTP transport and --unix for the AF_UNIX launcher
	// transport; default is stdio. Unknown launcher flags are tolerated (the
	// VGI extension varies argv to key its worker cache), so we filter to flags
	// we actually define before parsing.
	httpMode := flag.Bool("http", false, "Run as an HTTP server instead of stdio")
	unixPath := flag.String("unix", "", "Serve the AF_UNIX launcher transport on this socket path instead of stdio")
	logFlags := vgi.RegisterLoggingFlags(flag.CommandLine)
	_ = flag.CommandLine.Parse(filterKnownFlags(os.Args[1:], map[string]bool{
		"log-level":  true,
		"log-format": true,
		"log-logger": true,
		"unix":       true,
	}))
	if err := logFlags.Apply(); err != nil {
		log.Fatalf("logging flags: %v", err)
	}

	w := vgi.NewWorker(
		vgi.WithCatalogName(x509worker.CatalogName),
		vgi.WithCatalogComment("Parse X.509 certificates and inspect TLS endpoints"),
		vgi.WithCatalogTags(map[string]string{
			"source":       "vgi-x509",
			"vgi.title":    "X.509 Certificate & TLS Inspection",
			"vgi.keywords": x509worker.KeywordsJSON("x509, certificate, tls, ssl, pem, der, fingerprint, subject, issuer, expiry, sans, certificate authority, security, compliance"),
			"vgi.doc_llm": "Defensive X.509 / TLS inspection toolkit over SQL. Parse a certificate " +
				"(PEM text or DER bytes) and read its subject, issuer, serial, validity window, public-key and " +
				"signature algorithms, SHA-256 fingerprint, CA flag, expiry status, and subject alternative " +
				"names; dump every certificate field in long format; and connect to a live TLS host:port " +
				"(AUTHORIZED endpoints only) to return the presented certificate chain. Use to audit, triage, " +
				"and report on certificates and TLS endpoints for security and compliance.",
			"vgi.doc_md": "# X.509 Certificate & TLS Inspection for DuckDB\n\n" +
				"**Parse X.509 certificates and inspect live TLS endpoints directly in SQL** — read subjects, " +
				"issuers, validity windows, SHA-256 fingerprints, and subject alternative names (SANs) from PEM " +
				"or DER certificates, and pull the certificate chain a TLS server presents, all without leaving " +
				"DuckDB.\n\n" +
				"This is a defensive security and compliance toolkit for anyone who works with certificates at " +
				"scale: SREs auditing certificate expiry across a fleet, security engineers triaging TLS " +
				"configurations, and compliance teams reporting on certificate authorities, key algorithms, and " +
				"signature algorithms. Instead of shelling out to `openssl` and parsing text by hand, you query " +
				"certificates and endpoints as ordinary SQL columns and rows, then filter, join, and aggregate " +
				"them like any other DuckDB data.\n\n" +
				"It is powered entirely by the Go standard library's battle-tested " +
				"[`crypto/x509`](https://pkg.go.dev/crypto/x509) and " +
				"[`crypto/tls`](https://pkg.go.dev/crypto/tls) packages — no third-party parsing code and no " +
				"external services. The worker speaks the VGI protocol over Arrow, so DuckDB attaches it as a " +
				"catalog and certificate parsing runs in-process at native speed. Certificate inputs are " +
				"accepted as **PEM text** (`VARCHAR`) or **DER bytes** (`BLOB`); the format is sniffed from the " +
				"content at runtime, so one query works for both.\n\n" +
				"## When to reach for it\n\n" +
				"Reach for this worker whenever certificates or TLS endpoints show up in your data and you want " +
				"to treat them as structured columns rather than opaque blobs: auditing expiry windows across a " +
				"fleet, pinning or comparing SHA-256 fingerprints, checking key and signature algorithms against " +
				"a policy, expanding a certificate into a row per attribute for ad-hoc inspection, or pulling the " +
				"chain a live server presents to confirm what it actually serves. Offline certificate parsing " +
				"runs entirely in-process; live endpoint inspection **opens a network connection, so use it " +
				"against AUTHORIZED endpoints only.** Discover the exact functions by listing the schema.\n\n" +
				"## Typical uses\n\n" +
				"A few patterns recur. To flag soon-to-expire certificates, apply `cert_not_after` to a " +
				"column of PEM or DER certificates and keep the rows whose expiry falls inside your renewal " +
				"window, reporting each certificate's `cert_subject` alongside. To audit cryptographic " +
				"hygiene across a fleet, group a certificate table by `cert_key_algorithm` and " +
				"`cert_signature_algorithm` and count the weak ones. To confirm what a server actually " +
				"serves, call the `tls_inspect` table function on an **authorized** `host:port` and read " +
				"back the presented chain. Browse the `cert_fields` registry view to discover every " +
				"attribute the worker can read and the scalar that returns each; ready-to-run, fully " +
				"qualified statements live in the `x509.main` schema's example queries.\n\n" +
				"Learn more about the underlying library in the " +
				"[Go `crypto/x509` documentation](https://pkg.go.dev/crypto/x509) and the " +
				"[Go source on GitHub](https://github.com/golang/go/tree/master/src/crypto/x509). " +
				"Source for this worker lives at " +
				"[github.com/Query-farm/vgi-x509](https://github.com/Query-farm/vgi-x509).",
			"vgi.author":             "Query.Farm",
			"vgi.copyright":          "Copyright 2026 Query Farm LLC - https://query.farm",
			"vgi.license":            "MIT",
			"vgi.support_contact":    "https://github.com/Query-farm/vgi-x509/issues",
			"vgi.support_policy_url": "https://github.com/Query-farm/vgi-x509/blob/main/README.md",
			// VGI152 / VGI920: analyst tasks for `vgi-lint simulate` (all offline).
			"vgi.agent_test_tasks": x509worker.AgentTestTasksJSON,
		}),
		vgi.WithCatalogInfo(vgi.CatalogInfo{
			Name:      x509worker.CatalogName,
			SourceURL: ptr("https://github.com/Query-farm/vgi-x509"),
		}),
		vgi.WithSchemaComments(map[string]string{
			"main": "X.509 certificate parsing and TLS endpoint inspection functions.",
		}),
		vgi.WithSchemaTags(map[string]map[string]string{
			"main": {
				"vgi.title": "x509 — main",
				"vgi.keywords": x509worker.KeywordsJSON("x509, certificate, tls, ssl, pem, der, cert_subject, cert_issuer, cert_fingerprint, " +
					"cert_sans, cert_info, tls_inspect, expiry, certificate authority"),
				// VGI123 classifying tags use BARE keys (NOT vgi.-namespaced).
				"domain":   "security",
				"category": "parsing",
				"topic":    "x509-certificates-and-tls",
				// Per-object vgi.source_url omitted (VGI139): provenance lives only on
				// the catalog object via WithCatalogInfo.SourceURL.
				"vgi.doc_llm": "X.509 certificate parsing and TLS inspection functions: read subject, " +
					"issuer, serial, validity window, key/signature algorithms, SHA-256 fingerprint, CA flag, " +
					"expiry status, and subject alternative names from a PEM/DER certificate; dump all fields in " +
					"long format; and fetch the certificate chain presented by a live TLS host:port.",
				"vgi.doc_md": "## x509.main\n\n" +
					"Defensive **X.509 certificate** parsing and **TLS endpoint** inspection, " +
					"exposed as DuckDB SQL functions over Apache Arrow.\n\n" +
					"### Two ways to work\n\n" +
					"Scalar functions take one certificate and return a single field (subject, issuer, serial, " +
					"key and signature algorithms, SHA-256 fingerprint, validity window, CA flag, or subject " +
					"alternative names) — ideal for filtering, joining, and aggregating certificate columns. Table " +
					"functions expand a certificate or endpoint into rows: one dumps every attribute of a " +
					"certificate for ad-hoc inspection, the other connects to a live TLS endpoint " +
					"(**AUTHORIZED endpoints only**) and returns the presented chain.\n\n" +
					"### Usage\n\n" +
					"Certificate inputs accept **PEM text** (`VARCHAR`) or **DER bytes** (`BLOB`); " +
					"the content is sniffed at runtime. NULL certificate input yields NULL " +
					"(scalars) or zero rows. List the schema to discover the exact functions.",
				// VGI413 category registry — each object tags a vgi.category naming one of these.
				"vgi.categories": x509worker.CategoriesJSON,
				// VGI506 representative example queries (catalog-qualified, executable).
				"vgi.example_queries": x509worker.SchemaExampleQueries,
			},
		}),
	)
	x509worker.Register(w)

	if *httpMode {
		if err := w.RunHttp("127.0.0.1:0"); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *unixPath != "" {
		// AF_UNIX launcher transport: serve on the given socket path. The SDK
		// prints "UNIX:<path>" once listening; idleTimeout=0 disables the
		// self-shutdown timer (the launcher/CI owns the process lifecycle).
		if err := w.RunUnix(*unixPath, 0); err != nil {
			log.Fatal(err)
		}
		return
	}
	w.RunStdio()
}

// ptr returns a pointer to v (for optional string fields like SourceURL).
func ptr[T any](v T) *T { return &v }

// filterKnownFlags drops argv tokens for flags this binary doesn't define, so
// launcher-injected differentiation flags don't abort flag parsing. Flags named
// in valueFlags consume the following token as their value.
func filterKnownFlags(args []string, valueFlags map[string]bool) []string {
	defined := map[string]bool{}
	flag.CommandLine.VisitAll(func(f *flag.Flag) { defined[f.Name] = true })
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		hasInlineValue := strings.ContainsRune(name, '=')
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if !defined[name] {
			continue
		}
		out = append(out, a)
		if valueFlags[name] && !hasInlineValue && i+1 < len(args) {
			i++
			out = append(out, args[i])
		}
	}
	return out
}
