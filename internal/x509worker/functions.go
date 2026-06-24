// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-rpc-go/vgirpc"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// CatalogName is the VGI catalog name advertised by this worker.
const CatalogName = "x509"

// IMPORTANT (gob-state gotcha): table-function state is gob-encoded by the SDK
// between NewState and Process (it may cross a process boundary). State structs
// must therefore hold only EXPORTED, gob-encodable fields — no arrow.Record, no
// interfaces, channels, funcs, or unexported fields. Each table function does
// all parsing / network work eagerly in NewState, stores plain exported Go
// slices plus a Done flag, and rebuilds the Arrow batch in Process.

// tsType is the Arrow timestamp type used for all TIMESTAMP outputs. No
// TimeZone is set so DuckDB sees a plain TIMESTAMP (not TIMESTAMPTZ); the
// underlying values are UTC wall-clock micros from the certificate.
var tsType = &arrow.TimestampType{Unit: arrow.Microsecond}

// Compile-time checks that the scalar functions satisfy the SDK interface.
var (
	_ vgi.ScalarFunction = (*certStringScalar)(nil)
	_ vgi.ScalarFunction = (*certBoolScalar)(nil)
	_ vgi.ScalarFunction = (*certTimestampScalar)(nil)
	_ vgi.ScalarFunction = (*certSANsScalar)(nil)
)

// ---------------------------------------------------------------------------
// PEM-vs-DER input dispatch.
//
// A certificate argument is declared with arrow_type "any" so DuckDB can pass
// it as either VARCHAR (PEM text) or BLOB (DER bytes). certBytesAt pulls the
// raw bytes out of whichever column type arrived; ParseCertificate then sniffs
// PEM-vs-DER on the content.
// ---------------------------------------------------------------------------

// certBytesAt extracts the raw certificate bytes from input column col at row i,
// supporting String/LargeString (PEM) and Binary/LargeBinary (DER) columns.
func certBytesAt(col arrow.Array, i int) ([]byte, bool) {
	switch c := col.(type) {
	case *array.String:
		return []byte(c.Value(i)), true
	case *array.LargeString:
		return []byte(c.Value(i)), true
	case *array.Binary:
		return c.Value(i), true
	case *array.LargeBinary:
		return c.Value(i), true
	default:
		return nil, false
	}
}

// certHandle wraps a parsed certificate for use by the scalar accessor funcs.
type certHandle struct{ cert *x509.Certificate }

// parseHandle parses the certificate at row i of col, returning a clear error.
func parseHandle(col arrow.Array, i int) (*certHandle, error) {
	raw, ok := certBytesAt(col, i)
	if !ok {
		return nil, fmt.Errorf("x509: unsupported certificate input column type %T (expected VARCHAR PEM or BLOB DER)", col)
	}
	c, err := ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	return &certHandle{c}, nil
}

// ===========================================================================
// Scalar functions (pure / offline). Each accepts one "any" cert argument and
// differs only in its return type + accessor. To avoid repeating the SDK
// boilerplate four times we have one struct per return-type family parameterised
// by a name, description and accessor func.
// ===========================================================================

// --- VARCHAR-returning scalars -------------------------------------------

type certStringScalar struct {
	name     string
	desc     string
	examples []vgi.CatalogExample
	fn       func(*certHandle) string
}

func (f *certStringScalar) Name() string { return f.name }
func (f *certStringScalar) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: f.desc,
		Stability:   vgi.StabilityConsistent,
		ReturnType:  arrow.BinaryTypes.String,
		Categories:  []string{"x509", "certificate"},
		Examples:    f.examples,
	}
}
func (f *certStringScalar) ArgumentSpecs() []vgi.ArgSpec {
	return []vgi.ArgSpec{{Name: "cert", Position: 0, ArrowType: "any", Doc: "Certificate as PEM text (VARCHAR) or DER bytes (BLOB)"}}
}
func (f *certStringScalar) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindResult(arrow.BinaryTypes.String)
}
func (f *certStringScalar) Process(_ context.Context, params *vgi.ProcessParams, batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	var firstErr error
	out, mapErr := vgi.MapColumn(params, batch, 0, array.NewStringBuilder,
		func(col arrow.Array, i int) string {
			h, err := parseHandle(col, i)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return ""
			}
			return f.fn(h)
		})
	if firstErr != nil {
		return nil, firstErr
	}
	return out, mapErr
}

// --- BOOLEAN-returning scalars -------------------------------------------

type certBoolScalar struct {
	name     string
	desc     string
	examples []vgi.CatalogExample
	fn       func(*certHandle) bool
}

func (f *certBoolScalar) Name() string { return f.name }
func (f *certBoolScalar) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: f.desc,
		Stability:   vgi.StabilityConsistent,
		ReturnType:  arrow.FixedWidthTypes.Boolean,
		Categories:  []string{"x509", "certificate"},
		Examples:    f.examples,
	}
}
func (f *certBoolScalar) ArgumentSpecs() []vgi.ArgSpec {
	return []vgi.ArgSpec{{Name: "cert", Position: 0, ArrowType: "any", Doc: "Certificate as PEM text (VARCHAR) or DER bytes (BLOB)"}}
}
func (f *certBoolScalar) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindResult(arrow.FixedWidthTypes.Boolean)
}
func (f *certBoolScalar) Process(_ context.Context, params *vgi.ProcessParams, batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	var firstErr error
	out, mapErr := vgi.MapColumn(params, batch, 0, array.NewBooleanBuilder,
		func(col arrow.Array, i int) bool {
			h, err := parseHandle(col, i)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return false
			}
			return f.fn(h)
		})
	if firstErr != nil {
		return nil, firstErr
	}
	return out, mapErr
}

// --- TIMESTAMP-returning scalars -----------------------------------------

type certTimestampScalar struct {
	name     string
	desc     string
	examples []vgi.CatalogExample
	fn       func(*certHandle) time.Time
}

func (f *certTimestampScalar) Name() string { return f.name }
func (f *certTimestampScalar) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: f.desc,
		Stability:   vgi.StabilityConsistent,
		ReturnType:  tsType,
		Categories:  []string{"x509", "certificate"},
		Examples:    f.examples,
	}
}
func (f *certTimestampScalar) ArgumentSpecs() []vgi.ArgSpec {
	return []vgi.ArgSpec{{Name: "cert", Position: 0, ArrowType: "any", Doc: "Certificate as PEM text (VARCHAR) or DER bytes (BLOB)"}}
}
func (f *certTimestampScalar) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindResult(tsType)
}
func (f *certTimestampScalar) Process(_ context.Context, params *vgi.ProcessParams, batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	col := batch.Column(0)
	n := int(batch.NumRows())
	b := array.NewTimestampBuilder(memory.NewGoAllocator(), tsType)
	defer b.Release()
	b.Reserve(n)
	var firstErr error
	for i := 0; i < n; i++ {
		if col.IsNull(i) {
			b.AppendNull()
			continue
		}
		h, err := parseHandle(col, i)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			b.AppendNull()
			continue
		}
		b.Append(arrow.Timestamp(f.fn(h).UnixMicro()))
	}
	if firstErr != nil {
		return nil, firstErr
	}
	arr := b.NewArray()
	defer arr.Release()
	return vgi.BuildResultBatch(params, arr, int64(n)), nil
}

// --- VARCHAR[]-returning scalar (cert_sans) ------------------------------

type certSANsScalar struct{}

func (f *certSANsScalar) Name() string { return "cert_sans" }
func (f *certSANsScalar) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Subject alternative names (DNS names + IP addresses) as a VARCHAR list",
		Stability:   vgi.StabilityConsistent,
		ReturnType:  arrow.ListOf(arrow.BinaryTypes.String),
		Categories:  []string{"x509", "certificate"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT x509.main.cert_sans('-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----');",
				Description: "List the subject alternative names (DNS names and IP addresses) of a PEM certificate.",
			},
		},
	}
}
func (f *certSANsScalar) ArgumentSpecs() []vgi.ArgSpec {
	return []vgi.ArgSpec{{Name: "cert", Position: 0, ArrowType: "any", Doc: "Certificate as PEM text (VARCHAR) or DER bytes (BLOB)"}}
}
func (f *certSANsScalar) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindResult(arrow.ListOf(arrow.BinaryTypes.String))
}
func (f *certSANsScalar) Process(_ context.Context, params *vgi.ProcessParams, batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	col := batch.Column(0)
	n := int(batch.NumRows())
	lb := array.NewListBuilder(memory.NewGoAllocator(), arrow.BinaryTypes.String)
	defer lb.Release()
	vb := lb.ValueBuilder().(*array.StringBuilder)
	var firstErr error
	for i := 0; i < n; i++ {
		if col.IsNull(i) {
			lb.AppendNull()
			continue
		}
		h, err := parseHandle(col, i)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			lb.AppendNull()
			continue
		}
		lb.Append(true)
		for _, s := range SANs(h.cert) {
			vb.Append(s)
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	arr := lb.NewArray()
	defer arr.Release()
	return vgi.BuildResultBatch(params, arr, int64(n)), nil
}

// ===========================================================================
// Table functions.
// ===========================================================================

// WHY AN EXPLICIT CURSOR, NOT A bool Done (the HTTP-continuation fix):
//
// Over the HTTP transport the worker is STATELESS across exchanges — there is no
// long-lived process holding the live state between Process ticks. The framework
// round-trips the producer state through an opaque continuation token: after each
// tick it gob-encodes the state (snapshotting the LIVE user state), the client
// returns the token, and the worker resumes by gob-decoding it. The HTTP server
// emits at most one data batch per response, so a producer with more to emit is
// always resumed mid-stream from its token.
//
// The position MUST therefore live in the serialized state. A bare `Done bool`
// flipped only AFTER the single Emit does not survive the continuation boundary:
// the resumed tick observes the pre-Emit snapshot, re-emits the same rows, and
// the scan never terminates (an infinite loop — subprocess/unix keep live state
// in memory, so they were unaffected and hid the bug). Carrying an explicit
// Offset that Process advances BEFORE yielding makes the snapshot authoritative.
//
// rowsPerTick bounds how many rows each Process tick emits, so the cursor is
// observable across the continuation boundary (and scales to large results).
const rowsPerTick = 256

// cursorBounds returns [start,end) for the next bounded slice over n rows
// starting at *offset, advancing *offset past it; done=true once all consumed.
func cursorBounds(n int, offset *int) (start, end int, done bool) {
	if *offset >= n {
		return 0, 0, true
	}
	start = *offset
	end = start + rowsPerTick
	if end > n {
		end = n
	}
	*offset = end
	return start, end, false
}

// --- cert_info(cert) -> (field, value) -----------------------------------

var certInfoSchema = arrow.NewSchema([]arrow.Field{
	{Name: "field", Type: arrow.BinaryTypes.String},
	{Name: "value", Type: arrow.BinaryTypes.String},
}, nil)

type certInfoArgs struct {
	Cert []byte `vgi:"pos=0,type=any,doc=Certificate as PEM text (VARCHAR) or DER bytes (BLOB)"`
}

// certInfoState holds the flattened (field,value) rows (gob-encodable) plus the
// cursor offset of the next unemitted row.
type certInfoState struct {
	Fields []string
	Values []string
	Offset int
}

type certInfoFunc struct{}

var _ vgi.TypedTableFunc[certInfoState] = (*certInfoFunc)(nil)

func (f *certInfoFunc) Name() string { return "cert_info" }
func (f *certInfoFunc) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Long-format dump of all certificate attributes (one row per field)",
		Stability:   vgi.StabilityConsistent,
		Categories:  []string{"x509", "certificate"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT * FROM x509.main.cert_info('-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----');",
				Description: "Dump every attribute of a PEM certificate as (field, value) rows.",
			},
		},
		Tags: map[string]string{
			"vgi.columns_md": "| column | type | description |\n" +
				"|---|---|---|\n" +
				"| `field` | VARCHAR | The certificate attribute name (e.g. `subject`, `issuer`, `serial`, `not_after`, `is_ca`). |\n" +
				"| `value` | VARCHAR | The attribute's value rendered as text. |",
		},
	}
}
func (f *certInfoFunc) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(certInfoArgs{}) }
func (f *certInfoFunc) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(certInfoSchema)
}
func (f *certInfoFunc) NewState(params *vgi.ProcessParams) (*certInfoState, error) {
	col, err := params.Args.GetColumn(0)
	if err != nil {
		return nil, err
	}
	if col.Len() == 0 || col.IsNull(0) {
		return &certInfoState{}, nil
	}
	h, err := parseHandle(col, 0)
	if err != nil {
		return nil, err
	}
	rows := CertInfo(h.cert, time.Now())
	st := &certInfoState{}
	for _, r := range rows {
		st.Fields = append(st.Fields, r.Field)
		st.Values = append(st.Values, r.Value)
	}
	return st, nil
}
func (f *certInfoFunc) Process(_ context.Context, _ *vgi.ProcessParams, state *certInfoState, out *vgirpc.OutputCollector) error {
	start, end, done := cursorBounds(len(state.Fields), &state.Offset)
	if done {
		return out.Finish()
	}
	fields := state.Fields[start:end]
	values := state.Values[start:end]
	n := int64(len(fields))
	batch := array.NewRecordBatch(certInfoSchema, []arrow.Array{
		vgi.BuildStringArray(n, func(i int64) string { return fields[i] }),
		vgi.BuildStringArray(n, func(i int64) string { return values[i] }),
	}, n)
	defer batch.Release()
	return out.Emit(batch)
}

// --- tls_inspect(host_port, ...) -> chain --------------------------------

var tlsInspectSchema = arrow.NewSchema([]arrow.Field{
	{Name: "seq", Type: arrow.PrimitiveTypes.Int32},
	{Name: "subject", Type: arrow.BinaryTypes.String},
	{Name: "issuer", Type: arrow.BinaryTypes.String},
	{Name: "not_before", Type: tsType},
	{Name: "not_after", Type: tsType},
	{Name: "is_ca", Type: arrow.FixedWidthTypes.Boolean},
	{Name: "fingerprint", Type: arrow.BinaryTypes.String},
}, nil)

type tlsInspectArgs struct {
	HostPort   string `vgi:"pos=0,doc=Endpoint to inspect as host:port (AUTHORIZED endpoints only)"`
	TimeoutMs  int64  `vgi:"name=timeout_ms,default=10000,doc=Dial+handshake timeout in milliseconds"`
	Insecure   bool   `vgi:"name=insecure,default=true,doc=Skip chain verification (default true: inspect anything)"`
	ServerName string `vgi:"name=server_name,default=,doc=SNI server name (default: host portion of host:port)"`
}

// tlsChainRow is one gob-encodable certificate row from a TLS chain.
type tlsChainRow struct {
	Seq         int32
	Subject     string
	Issuer      string
	NotBeforeUS int64
	NotAfterUS  int64
	IsCA        bool
	Fingerprint string
}

type tlsInspectState struct {
	Rows   []tlsChainRow
	Offset int
}

type tlsInspectFunc struct{}

var _ vgi.TypedTableFunc[tlsInspectState] = (*tlsInspectFunc)(nil)

func (f *tlsInspectFunc) Name() string { return "tls_inspect" }
func (f *tlsInspectFunc) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Connect to a TLS host:port and return the presented certificate chain (AUTHORIZED endpoints only)",
		Stability:   vgi.StabilityVolatile,
		Categories:  []string{"x509", "tls"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT * FROM x509.main.tls_inspect('example.com:443');",
				Description: "Connect to a TLS endpoint (AUTHORIZED endpoints only) and return the presented certificate chain.",
			},
		},
		Tags: map[string]string{
			"vgi.columns_md": "| column | type | description |\n" +
				"|---|---|---|\n" +
				"| `seq` | INTEGER | Position in the presented chain (0 = leaf/server certificate). |\n" +
				"| `subject` | VARCHAR | Certificate subject as an RFC 2253 distinguished name. |\n" +
				"| `issuer` | VARCHAR | Certificate issuer as an RFC 2253 distinguished name. |\n" +
				"| `not_before` | TIMESTAMP | Start of the certificate validity window (UTC). |\n" +
				"| `not_after` | TIMESTAMP | End of the certificate validity window (UTC). |\n" +
				"| `is_ca` | BOOLEAN | Whether the certificate is a CA certificate. |\n" +
				"| `fingerprint` | VARCHAR | SHA-256 fingerprint of the certificate (lowercase hex). |",
		},
	}
}
func (f *tlsInspectFunc) ArgumentSpecs() []vgi.ArgSpec { return vgi.DeriveArgSpecs(tlsInspectArgs{}) }
func (f *tlsInspectFunc) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(tlsInspectSchema)
}
func (f *tlsInspectFunc) NewState(params *vgi.ProcessParams) (*tlsInspectState, error) {
	var args tlsInspectArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	if params.Args.IsNull(0) {
		return &tlsInspectState{}, nil
	}
	chain, err := InspectTLS(context.Background(), args.HostPort, TLSInspectOptions{
		Timeout:    time.Duration(args.TimeoutMs) * time.Millisecond,
		Insecure:   args.Insecure,
		ServerName: args.ServerName,
	})
	if err != nil {
		return nil, err
	}
	st := &tlsInspectState{}
	for i, c := range chain {
		st.Rows = append(st.Rows, tlsChainRow{
			Seq:         int32(i),
			Subject:     Subject(c),
			Issuer:      Issuer(c),
			NotBeforeUS: NotBefore(c).UnixMicro(),
			NotAfterUS:  NotAfter(c).UnixMicro(),
			IsCA:        IsCA(c),
			Fingerprint: Fingerprint(c),
		})
	}
	return st, nil
}
func (f *tlsInspectFunc) Process(_ context.Context, _ *vgi.ProcessParams, state *tlsInspectState, out *vgirpc.OutputCollector) error {
	start, end, done := cursorBounds(len(state.Rows), &state.Offset)
	if done {
		return out.Finish()
	}
	r := state.Rows[start:end]
	n := int64(len(r))

	mem := memory.NewGoAllocator()
	seqB := array.NewInt32Builder(mem)
	defer seqB.Release()
	nbB := array.NewTimestampBuilder(mem, tsType)
	defer nbB.Release()
	naB := array.NewTimestampBuilder(mem, tsType)
	defer naB.Release()
	caB := array.NewBooleanBuilder(mem)
	defer caB.Release()
	seqB.Reserve(int(n))
	nbB.Reserve(int(n))
	naB.Reserve(int(n))
	caB.Reserve(int(n))
	for i := range r {
		seqB.Append(r[i].Seq)
		nbB.Append(arrow.Timestamp(r[i].NotBeforeUS))
		naB.Append(arrow.Timestamp(r[i].NotAfterUS))
		caB.Append(r[i].IsCA)
	}
	seqArr := seqB.NewArray()
	defer seqArr.Release()
	nbArr := nbB.NewArray()
	defer nbArr.Release()
	naArr := naB.NewArray()
	defer naArr.Release()
	caArr := caB.NewArray()
	defer caArr.Release()

	batch := array.NewRecordBatch(tlsInspectSchema, []arrow.Array{
		seqArr,
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Subject }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Issuer }),
		nbArr,
		naArr,
		caArr,
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Fingerprint }),
	}, n)
	defer batch.Release()
	return out.Emit(batch)
}

// ===========================================================================
// Registration.
// ===========================================================================

// certExamples builds a single catalog-qualified example query for a scalar that
// takes one certificate argument. The SQL is intentionally illustrative (a PEM
// placeholder) and references the catalog-qualified function name so vgi-lint's
// metadata-quality checks see a usable example per function.
func certExamples(fn, desc string) []vgi.CatalogExample {
	return []vgi.CatalogExample{
		{
			SQL:         "SELECT x509.main." + fn + "('-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----');",
			Description: desc,
		},
	}
}

// Register registers every x509 function on the worker.
func Register(w *vgi.Worker) {
	w.RegisterScalar(&certStringScalar{"cert_subject", "Certificate subject as an RFC 2253 distinguished name", certExamples("cert_subject", "Read the subject distinguished name of a PEM certificate."), func(h *certHandle) string { return Subject(h.cert) }})
	w.RegisterScalar(&certStringScalar{"cert_issuer", "Certificate issuer as an RFC 2253 distinguished name", certExamples("cert_issuer", "Read the issuer distinguished name of a PEM certificate."), func(h *certHandle) string { return Issuer(h.cert) }})
	w.RegisterScalar(&certStringScalar{"cert_serial", "Certificate serial number (decimal string)", certExamples("cert_serial", "Read the serial number of a PEM certificate as a decimal string."), func(h *certHandle) string { return Serial(h.cert) }})
	w.RegisterScalar(&certStringScalar{"cert_key_algorithm", "Public-key algorithm with size/curve (e.g. RSA-2048, ECDSA-P256)", certExamples("cert_key_algorithm", "Read the public-key algorithm and size/curve of a PEM certificate."), func(h *certHandle) string { return KeyAlgorithm(h.cert) }})
	w.RegisterScalar(&certStringScalar{"cert_signature_algorithm", "Certificate signature algorithm", certExamples("cert_signature_algorithm", "Read the signature algorithm of a PEM certificate."), func(h *certHandle) string { return SignatureAlgorithm(h.cert) }})
	w.RegisterScalar(&certStringScalar{"cert_fingerprint", "SHA-256 fingerprint of the certificate (lowercase hex)", certExamples("cert_fingerprint", "Compute the SHA-256 fingerprint of a PEM certificate (lowercase hex)."), func(h *certHandle) string { return Fingerprint(h.cert) }})

	w.RegisterScalar(&certBoolScalar{"cert_is_expired", "Whether the certificate is outside its validity window now", certExamples("cert_is_expired", "Check whether a PEM certificate is currently outside its validity window."), func(h *certHandle) bool { return IsExpired(h.cert, time.Now()) }})
	w.RegisterScalar(&certBoolScalar{"cert_is_ca", "Whether the certificate is a CA certificate", certExamples("cert_is_ca", "Check whether a PEM certificate is a CA certificate."), func(h *certHandle) bool { return IsCA(h.cert) }})

	w.RegisterScalar(&certTimestampScalar{"cert_not_before", "Start of the certificate validity window (UTC)", certExamples("cert_not_before", "Read the start of a PEM certificate's validity window (UTC)."), func(h *certHandle) time.Time { return NotBefore(h.cert) }})
	w.RegisterScalar(&certTimestampScalar{"cert_not_after", "End of the certificate validity window (UTC)", certExamples("cert_not_after", "Read the expiry (end of validity window) of a PEM certificate (UTC)."), func(h *certHandle) time.Time { return NotAfter(h.cert) }})

	w.RegisterScalar(&certSANsScalar{})

	w.RegisterTable(vgi.AsTableFunction[certInfoState](&certInfoFunc{}))
	w.RegisterTable(vgi.AsTableFunction[tlsInspectState](&tlsInspectFunc{}))
}
