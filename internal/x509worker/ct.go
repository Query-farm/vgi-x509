// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Query-farm/vgi-x509/internal/ctsample"
)

// This file implements Certificate Transparency (CT) search over the free,
// keyless crt.sh JSON API. crt.sh indexes the public CT logs, so a search is a
// PASSIVE lookup of public data: it never contacts the hosts being searched
// for. Identities in the reserved sample domain vgi-x509.example are answered
// offline from internal/ctsample (see CTClient.Sample). crt.sh is a shared community service that is often slow and answers
// HTTP 429 / 5xx under load, so every request is bounded by a timeout and
// retried with exponential backoff on 429, 5xx and transport errors.

// DefaultCTBaseURL is the crt.sh endpoint. Tests and private mirrors override
// it with the base_url option.
const DefaultCTBaseURL = "https://crt.sh/"

// DefaultCTTimeout bounds one crt.sh HTTP attempt. crt.sh routinely takes tens
// of seconds on a busy wildcard query.
const DefaultCTTimeout = 60 * time.Second

// DefaultCTRetries is how many times a failed (429 / 5xx / transport error)
// request is retried before giving up.
const DefaultCTRetries = 3

// ctBackoff is the first retry delay; each later retry doubles it. A variable
// so unit tests can shrink it.
var ctBackoff = 500 * time.Millisecond

// maxRetryAfter caps how long a Retry-After header can make us wait.
const maxRetryAfter = 30 * time.Second

// maxCTBody caps a crt.sh response body (a broad wildcard can return many MB).
const maxCTBody = 256 << 20

// ctUserAgent identifies the worker to crt.sh.
const ctUserAgent = "vgi-x509 (+https://github.com/Query-farm/vgi-x509)"

// CTClient talks to crt.sh (or a compatible mock / mirror).
type CTClient struct {
	BaseURL    string
	HTTP       *http.Client
	MaxRetries int
	// Sample answers identities in the reserved sample domain (and the sample
	// certificate IDs) from the built-in offline log (internal/ctsample)
	// instead of the network. NewCTClient sets it only for the default crt.sh
	// endpoint, so a base_url override always goes over HTTP.
	Sample bool
}

// NewCTClient builds a client. An empty baseURL means crt.sh; a non-positive
// timeout means DefaultCTTimeout; a negative retries means DefaultCTRetries.
func NewCTClient(baseURL string, timeout time.Duration, retries int) *CTClient {
	sample := false
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultCTBaseURL
		sample = true
	}
	if timeout <= 0 {
		timeout = DefaultCTTimeout
	}
	if retries < 0 {
		retries = DefaultCTRetries
	}
	return &CTClient{BaseURL: baseURL, HTTP: &http.Client{Timeout: timeout}, MaxRetries: retries, Sample: sample}
}

// CTSearchOptions maps onto crt.sh's search parameters.
type CTSearchOptions struct {
	// ExcludeExpired sends exclude=expired.
	ExcludeExpired bool
	// Deduplicate sends deduplicate=Y (one row per certificate rather than a
	// precertificate plus its final certificate).
	Deduplicate bool
}

// CTEntry is one parsed crt.sh search result.
type CTEntry struct {
	ID             int64
	IssuerCAID     int64
	IssuerName     string
	CommonName     string
	SANs           []string
	SerialNumber   string
	NotBefore      time.Time
	NotAfter       time.Time
	EntryTimestamp time.Time
}

// ctJSONEntry is crt.sh's JSON shape (name_value is newline-separated).
type ctJSONEntry struct {
	ID             int64  `json:"id"`
	IssuerCAID     int64  `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	SerialNumber   string `json:"serial_number"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	EntryTimestamp string `json:"entry_timestamp"`
}

// Search queries crt.sh for identity (an exact name such as example.com, or a
// LIKE pattern such as %.example.com) and returns the matches newest first
// (crt.sh ID descending).
func (c *CTClient) Search(ctx context.Context, identity string, opts CTSearchOptions) ([]CTEntry, error) {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return nil, errors.New("ct_search: empty query (pass a domain such as 'example.com' or a pattern such as '%.example.com')")
	}
	q := url.Values{}
	q.Set("q", identity)
	q.Set("output", "json")
	if opts.ExcludeExpired {
		q.Set("exclude", "expired")
	}
	if opts.Deduplicate {
		q.Set("deduplicate", "Y")
	}
	if c.Sample && ctsample.IsSampleIdentity(identity) {
		body, err := json.Marshal(ctsample.Search(identity, opts.ExcludeExpired, opts.Deduplicate, time.Now()))
		if err != nil {
			return nil, err
		}
		return parseCTSearch(identity, body)
	}
	body, status, err := c.get(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("ct_search %q: %w", identity, err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("ct_search %q: crt.sh answered HTTP %d: %s", identity, status, snippet(body))
	}
	return parseCTSearch(identity, body)
}

// parseCTSearch decodes a crt.sh JSON search body.
func parseCTSearch(identity string, body []byte) ([]CTEntry, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, nil
	}
	if !strings.HasPrefix(trimmed, "[") {
		return nil, fmt.Errorf("ct_search %q: crt.sh returned a non-JSON response (it is probably overloaded; retry later or narrow the query): %s", identity, snippet(body))
	}
	var raw []ctJSONEntry
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return nil, fmt.Errorf("ct_search %q: decode crt.sh JSON: %w", identity, err)
	}
	out := make([]CTEntry, 0, len(raw))
	for _, r := range raw {
		e := CTEntry{
			ID:           r.ID,
			IssuerCAID:   r.IssuerCAID,
			IssuerName:   r.IssuerName,
			CommonName:   r.CommonName,
			SANs:         splitNameValue(r.NameValue),
			SerialNumber: strings.ToLower(r.SerialNumber),
		}
		var err error
		if e.NotBefore, err = parseCTTime(r.NotBefore); err != nil {
			return nil, fmt.Errorf("ct_search %q: id %d not_before: %w", identity, r.ID, err)
		}
		if e.NotAfter, err = parseCTTime(r.NotAfter); err != nil {
			return nil, fmt.Errorf("ct_search %q: id %d not_after: %w", identity, r.ID, err)
		}
		if e.EntryTimestamp, err = parseCTTime(r.EntryTimestamp); err != nil {
			return nil, fmt.Errorf("ct_search %q: id %d entry_timestamp: %w", identity, r.ID, err)
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// parseCTTime parses crt.sh's zone-less UTC timestamps
// (2025-01-01T00:00:00, optionally with fractional seconds). Empty → zero time.
func parseCTTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02T15:04:05", strings.TrimSuffix(s, "Z"))
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// splitNameValue splits crt.sh's newline-separated name_value into a list,
// trimming whitespace and dropping blanks and duplicates (order preserved).
func splitNameValue(v string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, n := range strings.Split(v, "\n") {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// errCTNotFound reports a crt.sh certificate ID with no certificate.
var errCTNotFound = errors.New("certificate not found")

// FetchCertificate downloads the certificate crt.sh logged under id
// (GET ?d=<id>) and returns it as PEM text. An unknown id returns
// errCTNotFound.
func (c *CTClient) FetchCertificate(ctx context.Context, id int64) (string, error) {
	if c.Sample {
		if p, ok := ctsample.Certificate(id); ok {
			return p, nil
		}
	}
	q := url.Values{}
	q.Set("d", strconv.FormatInt(id, 10))
	body, status, err := c.get(ctx, q)
	if err != nil {
		return "", fmt.Errorf("ct_certificate %d: %w", id, err)
	}
	if status == http.StatusNotFound {
		return "", errCTNotFound
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("ct_certificate %d: crt.sh answered HTTP %d: %s", id, status, snippet(body))
	}
	der := body
	if block, _ := pem.Decode(body); block != nil {
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("ct_certificate %d: crt.sh returned a %q PEM block, not a CERTIFICATE", id, block.Type)
		}
		der = block.Bytes
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return "", fmt.Errorf("ct_certificate %d: crt.sh returned something that is not a certificate (%v): %s", id, err, snippet(body))
	}
	return strings.TrimRight(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "\n"), nil
}

// get issues GET base?<q>, retrying 429 / 5xx answers and transport errors with
// exponential backoff (honouring a short Retry-After). It returns the final
// status and body; err is set only when no HTTP answer arrived at all, or the
// last answer was still a retryable failure.
func (c *CTClient) get(ctx context.Context, q url.Values) ([]byte, int, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid base_url %q: %w", c.BaseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, 0, fmt.Errorf("invalid base_url %q: want an http:// or https:// URL", c.BaseURL)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.RawQuery = q.Encode()
	full := u.String()

	attempts := c.MaxRetries + 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, retryDelay(attempt, lastErr)); err != nil {
				return nil, 0, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", ctUserAgent)
		req.Header.Set("Accept", "application/json, application/pkix-cert, */*")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			lastErr = fmt.Errorf("GET %s: %w", full, err)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxCTBody))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("GET %s: read body: %w", full, readErr)
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = &retryableStatus{status: resp.StatusCode, retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")), body: body}
			continue
		}
		return body, resp.StatusCode, nil
	}
	var rs *retryableStatus
	if errors.As(lastErr, &rs) {
		return nil, 0, fmt.Errorf("crt.sh answered HTTP %d after %d attempt(s) (it rate-limits and is often overloaded; retry later, narrow the query, or raise max_retries): %s",
			rs.status, attempts, snippet(rs.body))
	}
	return nil, 0, fmt.Errorf("%w (after %d attempt(s); crt.sh is often slow, so consider a larger timeout_ms)", lastErr, attempts)
}

// retryableStatus records a 429 / 5xx answer.
type retryableStatus struct {
	status     int
	retryAfter time.Duration
	body       []byte
}

func (r *retryableStatus) Error() string { return fmt.Sprintf("HTTP %d", r.status) }

// retryDelay is the wait before retry number attempt (1-based): the server's
// Retry-After when given, else ctBackoff doubled per attempt.
func retryDelay(attempt int, lastErr error) time.Duration {
	var rs *retryableStatus
	if errors.As(lastErr, &rs) && rs.retryAfter >= 0 {
		return rs.retryAfter
	}
	return ctBackoff << (attempt - 1)
}

// parseRetryAfter reads a Retry-After header given in seconds, capped at
// maxRetryAfter. Absent or unparseable → -1 (use the backoff schedule).
func parseRetryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs < 0 {
		return -1
	}
	d := time.Duration(secs) * time.Second
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// snippet renders the start of a response body for an error message.
func snippet(body []byte) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}
