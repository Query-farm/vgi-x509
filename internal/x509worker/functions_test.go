// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"bytes"
	"context"
	"encoding/gob"
	"testing"
	"time"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-x509/internal/testca"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// pemCol builds a 1-row VARCHAR (String) column carrying a PEM cert.
func pemCol(pem []byte, null bool) arrow.RecordBatch {
	b := array.NewStringBuilder(memory.DefaultAllocator)
	defer b.Release()
	if null {
		b.AppendNull()
	} else {
		b.Append(string(pem))
	}
	arr := b.NewArray()
	defer arr.Release()
	schema := arrow.NewSchema([]arrow.Field{{Name: "cert", Type: arrow.BinaryTypes.String}}, nil)
	return array.NewRecordBatch(schema, []arrow.Array{arr}, 1)
}

// derCol builds a 1-row BLOB (Binary) column carrying a DER cert.
func derCol(der []byte) arrow.RecordBatch {
	b := array.NewBinaryBuilder(memory.DefaultAllocator, arrow.BinaryTypes.Binary)
	defer b.Release()
	b.Append(der)
	arr := b.NewArray()
	defer arr.Release()
	schema := arrow.NewSchema([]arrow.Field{{Name: "cert", Type: arrow.BinaryTypes.Binary}}, nil)
	return array.NewRecordBatch(schema, []arrow.Array{arr}, 1)
}

func stringParams(out arrow.DataType) *vgi.ProcessParams {
	return &vgi.ProcessParams{
		OutputSchema: arrow.NewSchema([]arrow.Field{{Name: "out", Type: out}}, nil),
	}
}

func TestCertSubjectScalar(t *testing.T) {
	g := mustGen(t, nil)
	f := &certStringScalar{"cert_subject", "", func(h *certHandle) string { return Subject(h.cert) }}

	// PEM input.
	batch := pemCol(g.PEM, false)
	defer batch.Release()
	out, err := f.Process(context.Background(), stringParams(arrow.BinaryTypes.String), batch)
	if err != nil {
		t.Fatalf("Process(PEM): %v", err)
	}
	defer out.Release()
	got := out.Column(0).(*array.String).Value(0)
	if got != Subject(g.Cert) {
		t.Errorf("PEM subject = %q, want %q", got, Subject(g.Cert))
	}

	// DER input through the same function.
	dbatch := derCol(g.DER)
	defer dbatch.Release()
	dout, err := f.Process(context.Background(), stringParams(arrow.BinaryTypes.String), dbatch)
	if err != nil {
		t.Fatalf("Process(DER): %v", err)
	}
	defer dout.Release()
	if dout.Column(0).(*array.String).Value(0) != Subject(g.Cert) {
		t.Errorf("DER subject mismatch")
	}
}

func TestCertScalarNullPropagation(t *testing.T) {
	f := &certStringScalar{"cert_subject", "", func(h *certHandle) string { return Subject(h.cert) }}
	batch := pemCol(nil, true)
	defer batch.Release()
	out, err := f.Process(context.Background(), stringParams(arrow.BinaryTypes.String), batch)
	if err != nil {
		t.Fatalf("Process(NULL): %v", err)
	}
	defer out.Release()
	if !out.Column(0).IsNull(0) {
		t.Errorf("NULL cert should yield NULL output")
	}
}

func TestCertScalarMalformedError(t *testing.T) {
	f := &certStringScalar{"cert_subject", "", func(h *certHandle) string { return Subject(h.cert) }}
	batch := pemCol([]byte("garbage not a cert"), false)
	defer batch.Release()
	_, err := f.Process(context.Background(), stringParams(arrow.BinaryTypes.String), batch)
	if err == nil {
		t.Errorf("malformed cert should surface an error")
	}
}

func TestCertBoolScalar(t *testing.T) {
	g := mustGen(t, nil)
	f := &certBoolScalar{"cert_is_ca", "", func(h *certHandle) bool { return IsCA(h.cert) }}
	batch := pemCol(g.PEM, false)
	defer batch.Release()
	out, err := f.Process(context.Background(), stringParams(arrow.FixedWidthTypes.Boolean), batch)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	defer out.Release()
	if out.Column(0).(*array.Boolean).Value(0) != false {
		t.Errorf("cert_is_ca = true, want false")
	}
}

func TestCertTimestampScalar(t *testing.T) {
	g := mustGen(t, nil)
	f := &certTimestampScalar{"cert_not_after", "", func(h *certHandle) time.Time { return NotAfter(h.cert) }}
	batch := pemCol(g.PEM, false)
	defer batch.Release()
	out, err := f.Process(context.Background(), stringParams(tsType), batch)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	defer out.Release()
	ts := out.Column(0).(*array.Timestamp)
	if ts.Value(0).ToTime(arrow.Microsecond).Unix() != NotAfter(g.Cert).Unix() {
		t.Errorf("cert_not_after timestamp mismatch")
	}
}

func TestCertSANsScalar(t *testing.T) {
	g := mustGen(t, nil)
	f := &certSANsScalar{}
	batch := pemCol(g.PEM, false)
	defer batch.Release()
	out, err := f.Process(context.Background(), stringParams(arrow.ListOf(arrow.BinaryTypes.String)), batch)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	defer out.Release()
	list := out.Column(0).(*array.List)
	values := list.ListValues().(*array.String)
	if values.Len() != len(SANs(g.Cert)) {
		t.Errorf("cert_sans produced %d values, want %d", values.Len(), len(SANs(g.Cert)))
	}
}

func TestCertInfoFuncNewState(t *testing.T) {
	g := mustGen(t, nil)
	f := &certInfoFunc{}
	b := array.NewStringBuilder(memory.DefaultAllocator)
	b.Append(string(g.PEM))
	col := b.NewArray()
	b.Release()
	st, err := f.NewState(&vgi.ProcessParams{Args: &vgi.Arguments{Positional: []arrow.Array{col}}})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	if len(st.Fields) == 0 || len(st.Fields) != len(st.Values) {
		t.Errorf("cert_info rows malformed: %d fields, %d values", len(st.Fields), len(st.Values))
	}
}

func TestCertInfoFuncNull(t *testing.T) {
	f := &certInfoFunc{}
	b := array.NewStringBuilder(memory.DefaultAllocator)
	b.AppendNull()
	col := b.NewArray()
	b.Release()
	st, err := f.NewState(&vgi.ProcessParams{Args: &vgi.Arguments{Positional: []arrow.Array{col}}})
	if err != nil {
		t.Fatalf("NewState(NULL): %v", err)
	}
	if len(st.Fields) != 0 {
		t.Errorf("NULL cert should yield no rows, got %d", len(st.Fields))
	}
}

func TestTLSInspectFuncNewState(t *testing.T) {
	g := mustGen(t, func(s *testca.CertSpec) { s.CommonName = "tls.func.test" })
	addr := startTLSServer(t, g)

	f := &tlsInspectFunc{}
	hp := array.NewStringBuilder(memory.DefaultAllocator)
	hp.Append(addr)
	col := hp.NewArray()
	hp.Release()
	st, err := f.NewState(&vgi.ProcessParams{Args: &vgi.Arguments{Positional: []arrow.Array{col}}})
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	if len(st.Rows) != 1 {
		t.Fatalf("expected 1 chain row, got %d", len(st.Rows))
	}
	if st.Rows[0].Subject != Subject(g.Cert) {
		t.Errorf("subject = %q, want %q", st.Rows[0].Subject, Subject(g.Cert))
	}
	if st.Rows[0].Fingerprint != Fingerprint(g.Cert) {
		t.Errorf("fingerprint mismatch")
	}
}

func TestTLSInspectFuncUnreachable(t *testing.T) {
	f := &tlsInspectFunc{}
	hp := array.NewStringBuilder(memory.DefaultAllocator)
	hp.Append("127.0.0.1:1")
	col := hp.NewArray()
	hp.Release()
	to := array.NewInt64Builder(memory.DefaultAllocator)
	to.Append(2000)
	toCol := to.NewArray()
	to.Release()
	_, err := f.NewState(&vgi.ProcessParams{Args: &vgi.Arguments{
		Positional: []arrow.Array{col},
		Named:      map[string]arrow.Array{"timeout_ms": toCol},
	}})
	if err == nil {
		t.Errorf("unreachable host should surface an error")
	}
}

// TestCursorSurvivesContinuation mirrors the HTTP transport: the per-scan state
// is gob round-tripped between ticks, so the cursor offset must advance across
// the boundary and eventually drain. A bare Done flag flipped after Emit would
// re-emit row 0 forever; the explicit Offset terminates.
func TestCursorSurvivesContinuation(t *testing.T) {
	n := rowsPerTick*2 + 5 // spans 3 ticks
	fields := make([]string, n)
	values := make([]string, n)
	st := &certInfoState{Fields: fields, Values: values}
	emitted := 0
	for tick := 0; tick < 100; tick++ {
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(st); err != nil {
			t.Fatalf("gob encode: %v", err)
		}
		var resumed certInfoState
		if err := gob.NewDecoder(&buf).Decode(&resumed); err != nil {
			t.Fatalf("gob decode: %v", err)
		}
		st = &resumed
		start, end, done := cursorBounds(len(st.Fields), &st.Offset)
		if done {
			if emitted != n {
				t.Fatalf("drained after emitting %d of %d rows", emitted, n)
			}
			return
		}
		emitted += end - start
	}
	t.Fatal("cursor never drained — continuation loop did not terminate")
}

func TestRegisterDoesNotPanic(t *testing.T) {
	// Registration triggers the SDK's gob-encodability check on table-function
	// state; this guards against re-introducing a non-encodable state field.
	w := vgi.NewWorker(vgi.WithCatalogName(CatalogName))
	Register(w)
}
