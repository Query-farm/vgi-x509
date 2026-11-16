// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-rpc-go/vgirpc"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// Certificate Transparency functions: ct_search (table) and ct_certificate
// (scalar), both over crt.sh. See ct.go for the client.

// maxCertFetch bounds include_certificate: each row costs one more crt.sh
// request, and crt.sh rate-limits.
const maxCertFetch = 100

// --- ct_search(query, ...) -> CT log entries -------------------------------

var ctSearchSchema = arrow.NewSchema([]arrow.Field{
	{Name: "id", Type: arrow.PrimitiveTypes.Int64},
	{Name: "issuer_ca_id", Type: arrow.PrimitiveTypes.Int64},
	{Name: "issuer_name", Type: arrow.BinaryTypes.String},
	{Name: "common_name", Type: arrow.BinaryTypes.String},
	{Name: "sans", Type: arrow.ListOf(arrow.BinaryTypes.String)},
	{Name: "serial_number", Type: arrow.BinaryTypes.String},
	{Name: "not_before", Type: tsType},
	{Name: "not_after", Type: tsType},
	{Name: "entry_timestamp", Type: tsType},
	{Name: "pem", Type: arrow.BinaryTypes.String},
}, nil)

type ctSearchArgs struct {
	Query              string `vgi:"pos=0,doc=Domain to search the Certificate Transparency logs for: an exact name such as example.com or a SQL LIKE pattern such as %.example.com for every subdomain"`
	ExcludeExpired     bool   `vgi:"name=exclude_expired,default=false,doc=Drop certificates whose validity window has already ended (crt.sh exclude=expired)"`
	Deduplicate        bool   `vgi:"name=deduplicate,default=false,doc=Return one row per certificate instead of a precertificate plus its final certificate (crt.sh deduplicate=Y)"`
	MaxResults         int64  `vgi:"name=max_results,default=0,ge=0,doc=Keep only the newest N entries by crt.sh id (0 = all)"`
	IncludeCertificate bool   `vgi:"name=include_certificate,default=false,doc=Also download each certificate into the pem column (one extra crt.sh request per row so keep the result small with max_results)"`
	TimeoutMs          int64  `vgi:"name=timeout_ms,default=60000,ge=1,doc=Timeout for each crt.sh HTTP attempt in milliseconds"`
	MaxRetries         int64  `vgi:"name=max_retries,default=3,ge=0,le=10,doc=How many times to retry a crt.sh answer of HTTP 429 or 5xx or a network error with exponential backoff"`
	BaseURL            string `vgi:"name=base_url,default=,doc=Override the crt.sh endpoint (a mirror or test server); empty means https://crt.sh/"`
}

// ctSearchRow is one gob-encodable CT log entry (timestamps as UTC micros).
type ctSearchRow struct {
	ID               int64
	IssuerCAID       int64
	IssuerName       string
	CommonName       string
	SANs             []string
	SerialNumber     string
	NotBeforeUS      int64
	NotAfterUS       int64
	EntryTimestampUS int64
	HasPEM           bool
	PEM              string
}

type ctSearchState struct {
	Rows   []ctSearchRow
	Offset int
}

type ctSearchFunc struct{}

var _ vgi.TypedTableFunc[ctSearchState] = (*ctSearchFunc)(nil)

// ctSearchExamples is the ct_search example list, shared by the native Examples
// field and the vgi.example_queries tag. The first runs offline against the
// built-in sample log (the reserved vgi-x509.example domain), so it also serves
// as vgi-lint's scan probe; the live one queries crt.sh.
var ctSearchExamples = []vgi.CatalogExample{
	{
		SQL: "SELECT id, common_name, sans, not_after FROM x509.main.ct_search('%." + sampleDomain + "', " +
			"exclude_expired := true, deduplicate := true) ORDER BY id;",
		Description: "List the unexpired certificates logged for every subdomain of the sample domain, one row per " +
			"certificate (the reserved vgi-x509.example domain is answered offline from the worker's sample log).",
	},
	ComposedCTAuditExample,
	{
		SQL: "SELECT id, issuer_name, common_name, not_before, not_after FROM x509.main.ct_search('example.com', " +
			"exclude_expired := true, deduplicate := true, max_results := 5) ORDER BY not_before DESC;",
		Description: "Newest five unexpired certificates crt.sh has logged for example.com (live query to the public " +
			"crt.sh service, which can be slow).",
	},
}

func (f *ctSearchFunc) Name() string { return "ct_search" }
func (f *ctSearchFunc) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Search Certificate Transparency logs (crt.sh) for the certificates issued for a domain or %.domain pattern",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"x509", "certificate transparency"},
		Examples:    ctSearchExamples,
		Tags: merge(objectTags(
			"Certificate Transparency Search",
			"Search the public Certificate Transparency (CT) logs through the free, keyless crt.sh JSON "+
				"API and return one row per logged certificate: crt.sh id, issuing CA id and name, common "+
				"name, the SAN names as a `VARCHAR[]`, serial number (lowercase hex, as crt.sh reports it), "+
				"validity window and log entry time as UTC `TIMESTAMP`s, newest first. The query is an exact "+
				"domain (`example.com`) or a SQL LIKE pattern (`%.example.com` for every subdomain). "+
				"`exclude_expired` and `deduplicate` map to crt.sh's exclude=expired and deduplicate=Y (without "+
				"deduplicate a certificate usually appears twice: its precertificate and the final certificate). "+
				"`include_certificate := true` also downloads each certificate into the `pem` column (otherwise "+
				"NULL), which feeds straight into the cert_* scalars; `ct_certificate(id)` does the same per row. "+
				"This is a PASSIVE lookup of public log data: it never contacts the hosts being searched for. "+
				"crt.sh is a shared, often slow service that rate-limits, so each request is bounded by "+
				"`timeout_ms` and retried on HTTP 429 / 5xx with exponential backoff (`max_retries`); keep "+
				"wildcard queries narrow. The reserved sample domain vgi-x509.example is answered offline from "+
				"the worker's two sample certificates. NULL query yields zero rows.",
			"Search Certificate Transparency logs via crt.sh for the certificates issued for a domain or "+
				"`%.domain` pattern: id, issuer, names, serial, validity, log time (passive, public data).",
			"certificate transparency, ct, ct logs, crt.sh, certificate search, subdomain discovery, "+
				"issued certificates, precertificate, ct_search, x509, certificate",
		), map[string]string{
			// VGI307 / VGI414: structured static result schema.
			"vgi.result_columns_schema": resultColumnsSchemaJSON(
				resultColumn{"id", "BIGINT", "crt.sh certificate ID; pass it to ct_certificate or open https://crt.sh/?id=<id>."},
				resultColumn{"issuer_ca_id", "BIGINT", "crt.sh ID of the issuing certificate authority."},
				resultColumn{"issuer_name", "VARCHAR", "Issuer distinguished name as crt.sh renders it (e.g. C=US, O=Let's Encrypt, CN=R3)."},
				resultColumn{"common_name", "VARCHAR", "Subject common name of the logged certificate."},
				resultColumn{"sans", "VARCHAR[]", "Names the certificate covers (crt.sh name_value split on newlines): DNS names, sometimes e-mail addresses."},
				resultColumn{"serial_number", "VARCHAR", "Serial number as lowercase hex (cert_serial returns the same number in decimal)."},
				resultColumn{"not_before", "TIMESTAMP", "Start of the certificate validity window (UTC)."},
				resultColumn{"not_after", "TIMESTAMP", "End of the certificate validity window (UTC)."},
				resultColumn{"entry_timestamp", "TIMESTAMP", "When crt.sh first saw the certificate in a CT log (UTC)."},
				resultColumn{"pem", "VARCHAR", "The certificate as PEM text when include_certificate is true, else NULL."},
			),
			"vgi.category": CategoryCT,
			// VGI515: described example list as a tag (the native carrier drops descriptions).
			"vgi.example_queries": exampleQueriesJSON(ctSearchExamples),
		}),
	}
}
func (f *ctSearchFunc) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(ctSearchArgs{}) }
func (f *ctSearchFunc) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(ctSearchSchema)
}
func (f *ctSearchFunc) NewState(params *vgi.ProcessParams) (*ctSearchState, error) {
	var args ctSearchArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	if params.Args.IsNull(0) {
		return &ctSearchState{}, nil
	}
	if args.MaxResults < 0 {
		return nil, fmt.Errorf("ct_search: max_results must be >= 0, got %d", args.MaxResults)
	}
	if args.MaxRetries < 0 {
		return nil, fmt.Errorf("ct_search: max_retries must be >= 0, got %d", args.MaxRetries)
	}
	client := NewCTClient(args.BaseURL, time.Duration(args.TimeoutMs)*time.Millisecond, int(args.MaxRetries))
	ctx := context.Background()
	entries, err := client.Search(ctx, args.Query, CTSearchOptions{
		ExcludeExpired: args.ExcludeExpired,
		Deduplicate:    args.Deduplicate,
	})
	if err != nil {
		return nil, err
	}
	if args.MaxResults > 0 && int64(len(entries)) > args.MaxResults {
		entries = entries[:args.MaxResults]
	}
	if args.IncludeCertificate && len(entries) > maxCertFetch {
		return nil, fmt.Errorf("ct_search: include_certificate downloads one certificate per row and %d rows exceed the %d-row limit; "+
			"set max_results (or deduplicate / exclude_expired) to narrow the search", len(entries), maxCertFetch)
	}
	st := &ctSearchState{Rows: make([]ctSearchRow, 0, len(entries))}
	for _, e := range entries {
		row := ctSearchRow{
			ID:               e.ID,
			IssuerCAID:       e.IssuerCAID,
			IssuerName:       e.IssuerName,
			CommonName:       e.CommonName,
			SANs:             e.SANs,
			SerialNumber:     e.SerialNumber,
			NotBeforeUS:      e.NotBefore.UnixMicro(),
			NotAfterUS:       e.NotAfter.UnixMicro(),
			EntryTimestampUS: e.EntryTimestamp.UnixMicro(),
		}
		if args.IncludeCertificate {
			p, err := client.FetchCertificate(ctx, e.ID)
			switch {
			case errors.Is(err, errCTNotFound):
			case err != nil:
				return nil, err
			default:
				row.HasPEM, row.PEM = true, p
			}
		}
		st.Rows = append(st.Rows, row)
	}
	return st, nil
}
func (f *ctSearchFunc) Process(_ context.Context, _ *vgi.ProcessParams, state *ctSearchState, out *vgirpc.OutputCollector) error {
	start, end, done := cursorBounds(len(state.Rows), &state.Offset)
	if done {
		return out.Finish()
	}
	r := state.Rows[start:end]
	n := int64(len(r))

	mem := memory.NewGoAllocator()
	idB := array.NewInt64Builder(mem)
	defer idB.Release()
	caB := array.NewInt64Builder(mem)
	defer caB.Release()
	sansB := array.NewListBuilder(mem, arrow.BinaryTypes.String)
	defer sansB.Release()
	sanVals := sansB.ValueBuilder().(*array.StringBuilder)
	nbB := array.NewTimestampBuilder(mem, tsType)
	defer nbB.Release()
	naB := array.NewTimestampBuilder(mem, tsType)
	defer naB.Release()
	etB := array.NewTimestampBuilder(mem, tsType)
	defer etB.Release()
	pemB := array.NewStringBuilder(mem)
	defer pemB.Release()
	for i := range r {
		idB.Append(r[i].ID)
		caB.Append(r[i].IssuerCAID)
		sansB.Append(true)
		for _, s := range r[i].SANs {
			sanVals.Append(s)
		}
		nbB.Append(arrow.Timestamp(r[i].NotBeforeUS))
		naB.Append(arrow.Timestamp(r[i].NotAfterUS))
		etB.Append(arrow.Timestamp(r[i].EntryTimestampUS))
		if r[i].HasPEM {
			pemB.Append(r[i].PEM)
		} else {
			pemB.AppendNull()
		}
	}
	cols := []arrow.Array{
		idB.NewArray(),
		caB.NewArray(),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].IssuerName }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].CommonName }),
		sansB.NewArray(),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].SerialNumber }),
		nbB.NewArray(),
		naB.NewArray(),
		etB.NewArray(),
		pemB.NewArray(),
	}
	defer func() {
		for _, c := range cols {
			c.Release()
		}
	}()
	batch := array.NewRecordBatch(ctSearchSchema, cols, n)
	defer batch.Release()
	return out.Emit(batch)
}

// --- ct_certificate(id[, base_url]) -> PEM ---------------------------------

// ctCertificateScalar downloads the certificate crt.sh logged under an id. Two
// overloads: ct_certificate(id) uses crt.sh; ct_certificate(id, base_url)
// targets a mirror or test server.
type ctCertificateScalar struct{ withBaseURL bool }

var _ vgi.ScalarFunction = (*ctCertificateScalar)(nil)

// ctCertificateExamples is the ct_certificate example list (sample IDs are
// answered offline; see ctsample).
var ctCertificateExamples = []vgi.CatalogExample{
	{
		SQL: fmt.Sprintf("SELECT x509.main.cert_subject(x509.main.ct_certificate(%d)) AS subject;", sampleLeafID),
		Description: "Download a logged certificate by its crt.sh id and read its subject (the sample-log id used here " +
			"is answered offline; real ids come from ct_search).",
	},
	ComposedCTAuditExample,
}

func (f *ctCertificateScalar) Name() string { return "ct_certificate" }

// description differs per overload (vgi-lint VGI120: objects must not share
// a description).
func (f *ctCertificateScalar) description() string {
	if f.withBaseURL {
		return "Download the certificate logged under a crt.sh id from a given crt.sh-compatible endpoint, as PEM text"
	}
	return "Download the certificate crt.sh logged under an id, as PEM text"
}
func (f *ctCertificateScalar) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: f.description(),
		Stability:   vgi.StabilityConsistent,
		ReturnType:  arrow.BinaryTypes.String,
		Categories:  []string{"x509", "certificate transparency"},
		Examples:    ctCertificateExamples,
		Tags: merge(objectTags(
			"Certificate Transparency Download",
			"Download the certificate that crt.sh logged under a crt.sh id (the `id` column of ct_search) "+
				"and return it as PEM text (`VARCHAR`), ready for the cert_* scalars: e.g. "+
				"`cert_key_algorithm(ct_certificate(id))`. Calls crt.sh's `?d=<id>` endpoint once per distinct id, "+
				"with a 60-second timeout and up to 3 retries with exponential backoff on HTTP 429 / 5xx. A "+
				"passive lookup of public CT log data. An id crt.sh does not know yields NULL; NULL input yields "+
				"NULL. The two-argument form `ct_certificate(id, base_url)` targets a crt.sh mirror or test "+
				"server. Sample-log ids (from ct_search over the reserved vgi-x509.example domain) are answered "+
				"offline. For many rows prefer `ct_search(..., include_certificate := true)`.",
			"Download a logged certificate by crt.sh id as PEM text (passive, public CT data).",
			"certificate transparency, crt.sh, download certificate, pem, ct log entry, ct_certificate, "+
				"x509, certificate",
		), map[string]string{
			"vgi.category": CategoryCT,
			// VGI515: described example list as a tag (the native carrier drops descriptions).
			"vgi.example_queries": exampleQueriesJSON(ctCertificateExamples),
		}),
	}
}
func (f *ctCertificateScalar) ArgumentSpecs() []vgi.ArgSpec {
	specs := []vgi.ArgSpec{{Name: "id", Position: 0, ArrowType: "int64",
		Doc: "The crt.sh certificate ID of the logged certificate, as returned in the id column of ct_search"}}
	if f.withBaseURL {
		specs = append(specs, vgi.ArgSpec{Name: "base_url", Position: 1, ArrowType: "varchar",
			Doc: "The crt.sh endpoint to download from, such as a mirror or a test server; NULL or empty means https://crt.sh/"})
	}
	return specs
}
func (f *ctCertificateScalar) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindResult(arrow.BinaryTypes.String)
}
func (f *ctCertificateScalar) Process(ctx context.Context, params *vgi.ProcessParams, batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	n := int(batch.NumRows())
	ids, ok := batch.Column(0).(*array.Int64)
	if !ok {
		return nil, fmt.Errorf("ct_certificate: id must be BIGINT, got %s", batch.Column(0).DataType())
	}
	var bases *array.String
	if f.withBaseURL && batch.NumCols() > 1 {
		if bases, ok = batch.Column(1).(*array.String); !ok {
			return nil, fmt.Errorf("ct_certificate: base_url must be VARCHAR, got %s", batch.Column(1).DataType())
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	type result struct {
		pem   string
		found bool
	}
	clients := map[string]*CTClient{}
	cache := map[string]result{}
	b := array.NewStringBuilder(memory.NewGoAllocator())
	defer b.Release()
	for i := 0; i < n; i++ {
		if ids.IsNull(i) {
			b.AppendNull()
			continue
		}
		base := ""
		if bases != nil && !bases.IsNull(i) {
			base = bases.Value(i)
		}
		id := ids.Value(i)
		key := base + "\x00" + fmt.Sprint(id)
		res, seen := cache[key]
		if !seen {
			c := clients[base]
			if c == nil {
				c = NewCTClient(base, 0, -1)
				clients[base] = c
			}
			p, err := c.FetchCertificate(ctx, id)
			switch {
			case errors.Is(err, errCTNotFound):
			case err != nil:
				return nil, err
			default:
				res = result{pem: p, found: true}
			}
			cache[key] = res
		}
		if res.found {
			b.Append(res.pem)
		} else {
			b.AppendNull()
		}
	}
	arr := b.NewArray()
	defer arr.Release()
	return vgi.BuildResultBatch(params, arr, int64(n)), nil
}
