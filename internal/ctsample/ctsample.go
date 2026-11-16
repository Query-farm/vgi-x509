// Copyright 2026 Query Farm LLC - https://query.farm

// Package ctsample is a small, offline Certificate Transparency log in the
// shape of crt.sh's JSON search API, built over the two committed fixture
// certificates (internal/fixtures). It has two users:
//
//   - the worker, which answers ct_search / ct_certificate calls for the
//     reserved sample domain (SampleDomain, under the RFC 2606 .example TLD that
//     no CA may issue for, so crt.sh can never hold real entries for it) from
//     this log instead of crt.sh. That keeps the published examples and agent
//     tasks deterministic and runnable when crt.sh is slow or down.
//   - cmd/mockserver and the unit tests, which serve it over HTTP (Handler) as
//     a stand-in for crt.sh, so the network path (query parameters, retries,
//     error handling) is tested without the public internet.
//
// Handler answers the same two request shapes the worker sends to crt.sh:
//
//	GET /?q=<identity>&output=json[&exclude=expired][&deduplicate=Y]
//	GET /?d=<crt.sh certificate id>
//
// The identity matches like crt.sh: an exact name, or a pattern with % / _
// wildcards (e.g. %.vgi-x509.example), against the entry's common name and SAN
// names, case-insensitively. A few reserved identities simulate crt.sh's
// failure modes over HTTP (see the Identity* constants).
package ctsample

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Query-farm/vgi-x509/internal/fixtures"
)

// Reserved identities that simulate crt.sh failure modes.
const (
	// IdentityFlaky fails with HTTP 503 on every other request and otherwise
	// answers as if the query were legacy.vgi-x509.example, so a client with one
	// retry always succeeds.
	IdentityFlaky = "flaky.vgi-x509.example"
	// IdentityRateLimited always answers HTTP 429 with Retry-After: 0.
	IdentityRateLimited = "ratelimited.vgi-x509.example"
	// IdentityBroken answers HTTP 200 with an HTML body instead of JSON.
	IdentityBroken = "broken.vgi-x509.example"
	// IdentitySlow waits SlowDelay before answering an empty result.
	IdentitySlow = "slow.vgi-x509.example"
)

// SlowDelay is how long IdentitySlow stalls.
const SlowDelay = 3 * time.Second

// Entry is one crt.sh JSON search result, field for field.
type Entry struct {
	IssuerCAID     int64  `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
	ResultCount    int    `json:"result_count"`
}

// SampleDomain is the reserved domain the sample log covers.
const SampleDomain = "vgi-x509.example"

// Sample crt.sh certificate IDs. They sit far above any ID crt.sh will assign
// (its IDs are in the low tens of billions), so they never shadow a real one.
const (
	// TestPrecertID and TestLeafID are the precertificate and final certificate
	// logged for fixtures.TestPEM (crt.sh lists both unless deduplicate=Y).
	TestPrecertID int64 = 9100000000000000001
	TestLeafID    int64 = 9100000000000000002
	// LegacyID is the single entry for fixtures.LegacyPEM (expired in 2016).
	LegacyID int64 = 9100000000000000003
)

// IsSampleIdentity reports whether a ct_search identity falls inside
// SampleDomain (an exact name or a pattern ending in it).
func IsSampleIdentity(identity string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(identity)), SampleDomain)
}

// Certificate returns the PEM logged under a sample ID.
func Certificate(id int64) (string, bool) {
	p, ok := certificates[id]
	return p, ok
}

// Entries is the sample log.
var Entries = []Entry{
	{
		IssuerCAID: 9001, IssuerName: "O=VGI X509 Fixture, CN=test.vgi-x509.example",
		CommonName: "test.vgi-x509.example", NameValue: "alt.vgi-x509.example\ntest.vgi-x509.example",
		ID: TestLeafID, EntryTimestamp: "2025-01-01T00:10:00.5", NotBefore: "2025-01-01T00:00:00",
		NotAfter: "2035-01-01T00:00:00", SerialNumber: "3ade68b1", ResultCount: 3,
	},
	{
		IssuerCAID: 9001, IssuerName: "O=VGI X509 Fixture, CN=test.vgi-x509.example",
		CommonName: "test.vgi-x509.example", NameValue: "alt.vgi-x509.example\ntest.vgi-x509.example",
		ID: TestPrecertID, EntryTimestamp: "2025-01-01T00:05:00.25", NotBefore: "2025-01-01T00:00:00",
		NotAfter: "2035-01-01T00:00:00", SerialNumber: "3ade68b1", ResultCount: 3,
	},
	{
		IssuerCAID: 9002, IssuerName: "O=VGI X509 Fixture, CN=VGI X509 Fixture CA",
		CommonName: "legacy.vgi-x509.example", NameValue: "legacy.vgi-x509.example",
		ID: LegacyID, EntryTimestamp: "2015-01-01T00:01:02.003", NotBefore: "2015-01-01T00:00:00",
		NotAfter: "2016-01-01T00:00:00", SerialNumber: "03e9", ResultCount: 2,
	},
}

// certificates maps a crt.sh ID to the PEM crt.sh would serve for ?d=<id>.
var certificates = map[int64]string{
	TestPrecertID: fixtures.TestPEM,
	TestLeafID:    fixtures.TestPEM,
	LegacyID:      fixtures.LegacyPEM,
}

// Handler serves the sample log as a mock crt.sh. The zero value is ready to use.
type Handler struct {
	flaky atomic.Int64
	// Requests counts every request served (for retry assertions in tests).
	Requests atomic.Int64
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Requests.Add(1)
	q := r.URL.Query()
	if d := q.Get("d"); d != "" {
		h.serveCertificate(w, d)
		return
	}
	identity := q.Get("q")
	if identity == "" || q.Get("output") != "json" {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>crt.sh mock: use ?q=<identity>&output=json or ?d=<id></body></html>"))
		return
	}
	switch strings.ToLower(identity) {
	case IdentityRateLimited:
		w.Header().Set("Retry-After", "0")
		http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
		return
	case IdentityBroken:
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>crt.sh</title></head><body>Sorry, something went wrong</body></html>"))
		return
	case IdentitySlow:
		time.Sleep(SlowDelay)
		writeJSON(w, []Entry{})
		return
	case IdentityFlaky:
		if h.flaky.Add(1)%2 == 1 {
			http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		identity = "legacy.vgi-x509.example"
	}
	writeJSON(w, Search(identity, q.Get("exclude") == "expired", q.Get("deduplicate") == "Y", time.Now()))
}

func (h *Handler) serveCertificate(w http.ResponseWriter, d string) {
	id, err := strconv.ParseInt(d, 10, 64)
	if err != nil {
		http.Error(w, "Invalid value: "+d, http.StatusBadRequest)
		return
	}
	pemText, ok := Certificate(id)
	if !ok {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	_, _ = w.Write([]byte(pemText + "\n"))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Search returns the canned entries matching identity, honouring crt.sh's
// exclude=expired (drop entries whose not_after is before now) and
// deduplicate=Y (one entry per issuer + serial: the final certificate rather
// than its precertificate).
func Search(identity string, excludeExpired, deduplicate bool, now time.Time) []Entry {
	re := likePattern(identity)
	out := []Entry{}
	seen := map[string]bool{}
	for _, e := range Entries {
		if !matches(re, e) {
			continue
		}
		if excludeExpired {
			if na, err := time.Parse("2006-01-02T15:04:05", e.NotAfter); err == nil && na.Before(now) {
				continue
			}
		}
		if deduplicate {
			key := strconv.FormatInt(e.IssuerCAID, 10) + "/" + e.SerialNumber
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func matches(re *regexp.Regexp, e Entry) bool {
	if re.MatchString(e.CommonName) {
		return true
	}
	for _, n := range strings.Split(e.NameValue, "\n") {
		if re.MatchString(n) {
			return true
		}
	}
	return false
}

// likePattern compiles a crt.sh identity (SQL LIKE syntax) to a
// case-insensitive anchored regexp.
func likePattern(identity string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range identity {
		switch r {
		case '%':
			b.WriteString(".*")
		case '_':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}
