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
			"vgi.keywords": "x509, certificate, tls, ssl, pem, der, fingerprint, subject, issuer, expiry, sans, certificate authority, security, compliance",
			"vgi.doc_llm": "Defensive X.509 / TLS inspection toolkit over SQL. Parse a certificate " +
				"(PEM text or DER bytes) and read its subject, issuer, serial, validity window, public-key and " +
				"signature algorithms, SHA-256 fingerprint, CA flag, expiry status, and subject alternative " +
				"names; dump every certificate field in long format; and connect to a live TLS host:port " +
				"(AUTHORIZED endpoints only) to return the presented certificate chain. Use to audit, triage, " +
				"and report on certificates and TLS endpoints for security and compliance.",
			"vgi.doc_md": "# x509\n\n" +
				"Parse **X.509 certificates** and inspect **TLS endpoints**, exposed as DuckDB SQL functions. " +
				"A defensive security / compliance tool.\n\n" +
				"- Scalars: `cert_subject`, `cert_issuer`, `cert_serial`, `cert_key_algorithm`, " +
				"`cert_signature_algorithm`, `cert_fingerprint`, `cert_is_expired`, `cert_is_ca`, " +
				"`cert_not_before`, `cert_not_after`, `cert_sans` (offline certificate parsing).\n" +
				"- Table functions: `cert_info` (long-format field dump), `tls_inspect` (live TLS chain, " +
				"AUTHORIZED endpoints only).\n\n" +
				"Certificate inputs accept PEM text (VARCHAR) or DER bytes (BLOB).",
			"vgi.author":             "Query.Farm",
			"vgi.copyright":          "Copyright 2026 Query Farm LLC - https://query.farm",
			"vgi.license":            "MIT",
			"vgi.support_contact":    "https://github.com/Query-farm/vgi-x509/issues",
			"vgi.support_policy_url": "https://github.com/Query-farm/vgi-x509/blob/main/README.md",
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
				"vgi.keywords": "x509, certificate, tls, ssl, pem, der, cert_subject, cert_issuer, cert_fingerprint, " +
					"cert_sans, cert_info, tls_inspect, expiry, certificate authority",
				// VGI123 classifying tags use BARE keys (NOT vgi.-namespaced).
				"domain":         "security",
				"category":       "parsing",
				"topic":          "x509-certificates-and-tls",
				"vgi.source_url": "https://github.com/Query-farm/vgi-x509/blob/main/internal/x509worker/functions.go",
				"vgi.doc_llm": "X.509 certificate parsing and TLS inspection functions: read subject, " +
					"issuer, serial, validity window, key/signature algorithms, SHA-256 fingerprint, CA flag, " +
					"expiry status, and subject alternative names from a PEM/DER certificate; dump all fields in " +
					"long format; and fetch the certificate chain presented by a live TLS host:port.",
				"vgi.doc_md": "## x509.main\n\n" +
					"Defensive **X.509 certificate** parsing and **TLS endpoint** inspection, " +
					"exposed as DuckDB SQL functions over Apache Arrow.\n\n" +
					"### Scalars (offline certificate parsing)\n\n" +
					"`cert_subject`, `cert_issuer`, `cert_serial`, `cert_key_algorithm`, " +
					"`cert_signature_algorithm`, `cert_fingerprint`, `cert_is_expired`, " +
					"`cert_is_ca`, `cert_not_before`, `cert_not_after`, `cert_sans`.\n\n" +
					"### Table functions\n\n" +
					"- `cert_info(cert)` — long-format `(field, value)` dump of every attribute.\n" +
					"- `tls_inspect(host_port, ...)` — connect to a live TLS endpoint " +
					"(**AUTHORIZED endpoints only**) and return the presented certificate chain.\n\n" +
					"### Usage\n\n" +
					"Certificate inputs accept **PEM text** (`VARCHAR`) or **DER bytes** (`BLOB`); " +
					"the content is sniffed at runtime. NULL certificate input yields NULL " +
					"(scalars) or zero rows (`cert_info`).",
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
