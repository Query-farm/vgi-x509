// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"bytes"
	"context"
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-x509/internal/ctsample"
	"github.com/Query-farm/vgi-x509/internal/fixtures"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// startCTMock serves the sample log as a mock crt.sh and shrinks the retry
// backoff so retry tests stay fast.
func startCTMock(t *testing.T) (*httptest.Server, *ctsample.Handler) {
	t.Helper()
	h := &ctsample.Handler{}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := ctBackoff
	ctBackoff = time.Millisecond
	t.Cleanup(func() { ctBackoff = old })
	return srv, h
}

func TestParseCTSearch(t *testing.T) {
	body := `[{"issuer_ca_id":183267,"issuer_name":"C=US, O=Let's Encrypt, CN=R3","common_name":"example.com",
	"name_value":"example.com\nwww.example.com\nexample.com\n","id":10,"entry_timestamp":"2024-03-01T12:34:56.789",
	"not_before":"2024-03-01T11:00:00","not_after":"2024-05-30T11:00:00","serial_number":"04ABCDEF","result_count":2},
	{"issuer_ca_id":1,"issuer_name":"x","common_name":"a","name_value":"a","id":20,"entry_timestamp":"2024-01-01T00:00:00",
	"not_before":"2024-01-01T00:00:00","not_after":"2025-01-01T00:00:00","serial_number":"01"}]`
	got, err := parseCTSearch("example.com", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != 20 || got[1].ID != 10 {
		t.Fatalf("want newest-first ids [20 10], got %+v", got)
	}
	e := got[1]
	if strings.Join(e.SANs, ",") != "example.com,www.example.com" {
		t.Errorf("sans = %q", e.SANs)
	}
	if e.SerialNumber != "04abcdef" {
		t.Errorf("serial = %q", e.SerialNumber)
	}
	if want := time.Date(2024, 3, 1, 12, 34, 56, 789e6, time.UTC); !e.EntryTimestamp.Equal(want) {
		t.Errorf("entry_timestamp = %v, want %v", e.EntryTimestamp, want)
	}
	if want := time.Date(2024, 5, 30, 11, 0, 0, 0, time.UTC); !e.NotAfter.Equal(want) {
		t.Errorf("not_after = %v", e.NotAfter)
	}
	if _, err := parseCTSearch("x", []byte("<html>busy</html>")); err == nil || !strings.Contains(err.Error(), "non-JSON") {
		t.Errorf("HTML body: want non-JSON error, got %v", err)
	}
	if got, err := parseCTSearch("x", []byte("[]")); err != nil || len(got) != 0 {
		t.Errorf("empty: %v %v", got, err)
	}
}

func TestCTSearchOverHTTP(t *testing.T) {
	srv, _ := startCTMock(t)
	c := NewCTClient(srv.URL, 5*time.Second, 0)
	ctx := context.Background()
	cases := []struct {
		q       string
		opts    CTSearchOptions
		wantIDs []int64
	}{
		{"test.vgi-x509.example", CTSearchOptions{}, []int64{ctsample.TestLeafID, ctsample.TestPrecertID}},
		{"TEST.vgi-x509.example", CTSearchOptions{Deduplicate: true}, []int64{ctsample.TestLeafID}},
		{"%.vgi-x509.example", CTSearchOptions{}, []int64{ctsample.LegacyID, ctsample.TestLeafID, ctsample.TestPrecertID}},
		{"%.vgi-x509.example", CTSearchOptions{ExcludeExpired: true, Deduplicate: true}, []int64{ctsample.TestLeafID}},
		{"nothing.example", CTSearchOptions{}, nil},
	}
	for _, tc := range cases {
		got, err := c.Search(ctx, tc.q, tc.opts)
		if err != nil {
			t.Fatalf("%s: %v", tc.q, err)
		}
		var ids []int64
		for _, e := range got {
			ids = append(ids, e.ID)
		}
		if len(ids) != len(tc.wantIDs) {
			t.Fatalf("%s %+v: ids %v, want %v", tc.q, tc.opts, ids, tc.wantIDs)
		}
		for i := range ids {
			if ids[i] != tc.wantIDs[i] {
				t.Errorf("%s %+v: ids %v, want %v", tc.q, tc.opts, ids, tc.wantIDs)
			}
		}
	}
}

func TestCTSearchRetriesAndErrors(t *testing.T) {
	srv, h := startCTMock(t)
	ctx := context.Background()

	// One retry absorbs the mock's every-other-request 503.
	got, err := NewCTClient(srv.URL, 5*time.Second, 1).Search(ctx, ctsample.IdentityFlaky, CTSearchOptions{})
	if err != nil || len(got) != 1 || got[0].ID != ctsample.LegacyID {
		t.Fatalf("flaky with retry: %v %v", got, err)
	}
	// Without retries the next 503 surfaces.
	if _, err := NewCTClient(srv.URL, 5*time.Second, 0).Search(ctx, ctsample.IdentityFlaky, CTSearchOptions{}); err == nil ||
		!strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("flaky without retry: want HTTP 503 error, got %v", err)
	}

	before := h.Requests.Load()
	_, err = NewCTClient(srv.URL, 5*time.Second, 2).Search(ctx, ctsample.IdentityRateLimited, CTSearchOptions{})
	if err == nil || !strings.Contains(err.Error(), "HTTP 429 after 3 attempt(s)") {
		t.Fatalf("rate limited: got %v", err)
	}
	if n := h.Requests.Load() - before; n != 3 {
		t.Errorf("rate limited: %d requests, want 3", n)
	}

	if _, err := NewCTClient(srv.URL, 5*time.Second, 0).Search(ctx, ctsample.IdentityBroken, CTSearchOptions{}); err == nil ||
		!strings.Contains(err.Error(), "non-JSON") {
		t.Fatalf("broken: got %v", err)
	}

	start := time.Now()
	if _, err := NewCTClient(srv.URL, 200*time.Millisecond, 0).Search(ctx, ctsample.IdentitySlow, CTSearchOptions{}); err == nil ||
		!strings.Contains(err.Error(), "timeout_ms") {
		t.Fatalf("slow: got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("slow: timeout not enforced (%v)", time.Since(start))
	}

	if _, err := NewCTClient(srv.URL, time.Second, 0).Search(ctx, "  ", CTSearchOptions{}); err == nil {
		t.Errorf("empty query: want error")
	}
	if _, err := NewCTClient("ftp://x", time.Second, 0).Search(ctx, "a.example", CTSearchOptions{}); err == nil {
		t.Errorf("bad base_url: want error")
	}
}

func TestRetryAfter(t *testing.T) {
	if parseRetryAfter("") != -1 || parseRetryAfter("soon") != -1 {
		t.Errorf("unparseable Retry-After should be -1")
	}
	if parseRetryAfter("2") != 2*time.Second || parseRetryAfter("9999") != maxRetryAfter {
		t.Errorf("Retry-After seconds / cap wrong")
	}
	if d := retryDelay(3, nil); d != ctBackoff<<2 {
		t.Errorf("backoff for attempt 3 = %v", d)
	}
}

func TestCTFetchCertificate(t *testing.T) {
	srv, _ := startCTMock(t)
	c := NewCTClient(srv.URL, 5*time.Second, 0)
	p, err := c.FetchCertificate(context.Background(), ctsample.LegacyID)
	if err != nil {
		t.Fatal(err)
	}
	if p != fixtures.LegacyPEM {
		t.Errorf("fetched PEM differs from the fixture:\n%s", p)
	}
	if _, err := c.FetchCertificate(context.Background(), 1); err != errCTNotFound {
		t.Errorf("unknown id: want errCTNotFound, got %v", err)
	}
}

// The default (crt.sh) client answers the reserved sample domain offline and
// sends everything else to the network; a base_url override never uses it.
func TestCTSampleOffline(t *testing.T) {
	c := NewCTClient("", time.Second, 0)
	if !c.Sample || c.BaseURL != DefaultCTBaseURL {
		t.Fatalf("default client: %+v", c)
	}
	c.BaseURL = "http://127.0.0.1:1/" // would fail if it touched the network
	got, err := c.Search(context.Background(), "%.vgi-x509.example", CTSearchOptions{Deduplicate: true})
	if err != nil || len(got) != 2 {
		t.Fatalf("sample search: %v %v", got, err)
	}
	p, err := c.FetchCertificate(context.Background(), ctsample.TestLeafID)
	if err != nil || p != fixtures.TestPEM {
		t.Fatalf("sample fetch: %v", err)
	}
	if NewCTClient("http://mirror.example/", time.Second, 0).Sample {
		t.Errorf("base_url override must not use the sample log")
	}
}

func ctSearchParams(t *testing.T, query string, named map[string]any) *vgi.ProcessParams {
	t.Helper()
	mem := memory.DefaultAllocator
	qb := array.NewStringBuilder(mem)
	qb.Append(query)
	args := &vgi.Arguments{Positional: []arrow.Array{qb.NewArray()}, Named: map[string]arrow.Array{}}
	qb.Release()
	for k, v := range named {
		switch v := v.(type) {
		case string:
			b := array.NewStringBuilder(mem)
			b.Append(v)
			args.Named[k] = b.NewArray()
			b.Release()
		case bool:
			b := array.NewBooleanBuilder(mem)
			b.Append(v)
			args.Named[k] = b.NewArray()
			b.Release()
		case int:
			b := array.NewInt64Builder(mem)
			b.Append(int64(v))
			args.Named[k] = b.NewArray()
			b.Release()
		}
	}
	return &vgi.ProcessParams{Args: args}
}

func TestCTSearchFuncNewState(t *testing.T) {
	srv, _ := startCTMock(t)
	f := &ctSearchFunc{}
	st, err := f.NewState(ctSearchParams(t, "%.vgi-x509.example", map[string]any{
		"base_url": srv.URL, "include_certificate": true, "max_results": 2,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Rows) != 2 || st.Rows[0].ID != ctsample.LegacyID {
		t.Fatalf("rows: %+v", st.Rows)
	}
	r := st.Rows[0]
	if !r.HasPEM || r.PEM != fixtures.LegacyPEM || r.SerialNumber != "03e9" ||
		strings.Join(r.SANs, ",") != "legacy.vgi-x509.example" ||
		r.NotAfterUS != time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC).UnixMicro() {
		t.Errorf("legacy row: %+v", r)
	}

	// The state (with SAN lists) must survive the HTTP continuation's gob trip.
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(st); err != nil {
		t.Fatal(err)
	}
	var back ctSearchState
	if err := gob.NewDecoder(&buf).Decode(&back); err != nil {
		t.Fatal(err)
	}
	if len(back.Rows) != 2 || len(back.Rows[1].SANs) != 2 {
		t.Errorf("gob round trip lost rows: %+v", back.Rows)
	}

	if _, err := f.NewState(ctSearchParams(t, "x.example", map[string]any{"max_results": -1})); err == nil {
		t.Errorf("negative max_results: want error")
	}
}

func TestCTSearchFuncNull(t *testing.T) {
	b := array.NewStringBuilder(memory.DefaultAllocator)
	b.AppendNull()
	col := b.NewArray()
	b.Release()
	st, err := (&ctSearchFunc{}).NewState(&vgi.ProcessParams{Args: &vgi.Arguments{Positional: []arrow.Array{col}}})
	if err != nil || len(st.Rows) != 0 {
		t.Fatalf("NULL query: %v %v", st, err)
	}
}

func TestCTCertificateScalar(t *testing.T) {
	srv, h := startCTMock(t)
	mem := memory.DefaultAllocator
	ib := array.NewInt64Builder(mem)
	ib.AppendValues([]int64{ctsample.TestLeafID, 1, ctsample.TestLeafID}, nil)
	ib.AppendNull()
	ids := ib.NewArray()
	ib.Release()
	bb := array.NewStringBuilder(mem)
	for i := 0; i < 4; i++ {
		bb.Append(srv.URL)
	}
	bases := bb.NewArray()
	bb.Release()
	schema := arrow.NewSchema([]arrow.Field{
		{Name: "id", Type: arrow.PrimitiveTypes.Int64},
		{Name: "base_url", Type: arrow.BinaryTypes.String},
	}, nil)
	batch := array.NewRecordBatch(schema, []arrow.Array{ids, bases}, 4)
	defer batch.Release()

	before := h.Requests.Load()
	out, err := (&ctCertificateScalar{withBaseURL: true}).Process(context.Background(), stringParams(arrow.BinaryTypes.String), batch)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Release()
	col := out.Column(0).(*array.String)
	if col.Value(0) != fixtures.TestPEM || col.Value(2) != fixtures.TestPEM {
		t.Errorf("row 0/2 should be the fixture PEM")
	}
	if !col.IsNull(1) || !col.IsNull(3) {
		t.Errorf("unknown id and NULL id should be NULL")
	}
	if n := h.Requests.Load() - before; n != 2 {
		t.Errorf("%d requests, want 2 (the repeated id is cached)", n)
	}

	// The one-argument overload uses crt.sh, which answers sample ids offline
	// (only sample ids here, so the test never reaches the network).
	sb := array.NewInt64Builder(mem)
	sb.AppendValues([]int64{ctsample.TestLeafID, ctsample.LegacyID}, nil)
	sampleIDs := sb.NewArray()
	sb.Release()
	one := array.NewRecordBatch(arrow.NewSchema(schema.Fields()[:1], nil), []arrow.Array{sampleIDs}, 2)
	defer one.Release()
	out1, err := (&ctCertificateScalar{}).Process(context.Background(), stringParams(arrow.BinaryTypes.String), one)
	if err != nil {
		t.Fatalf("one-arg sample: %v", err)
	}
	defer out1.Release()
	if c := out1.Column(0).(*array.String); c.Value(0) != fixtures.TestPEM || c.Value(1) != fixtures.LegacyPEM {
		t.Errorf("one-arg overload did not return the sample certificate")
	}
}

// A 5xx on the download path surfaces as an error, not a silent NULL.
func TestCTFetchServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()
	old := ctBackoff
	ctBackoff = time.Millisecond
	defer func() { ctBackoff = old }()
	if _, err := NewCTClient(srv.URL, time.Second, 1).FetchCertificate(context.Background(), 5); err == nil ||
		!strings.Contains(err.Error(), "HTTP 502 after 2 attempt(s)") {
		t.Fatalf("got %v", err)
	}
}
