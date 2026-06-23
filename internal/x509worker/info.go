// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"crypto/x509"
	"strconv"
	"strings"
	"time"
)

// InfoField is one (field, value) pair in the long-format cert_info dump.
type InfoField struct {
	Field string
	Value string
}

// CertInfo returns the long-format (field, value) rows for a certificate: the
// same data the individual scalars expose, flattened into one row per
// attribute. now is used to compute the is_expired field.
func CertInfo(c *x509.Certificate, now time.Time) []InfoField {
	return []InfoField{
		{"subject", Subject(c)},
		{"issuer", Issuer(c)},
		{"serial", Serial(c)},
		{"not_before", NotBefore(c).Format(time.RFC3339)},
		{"not_after", NotAfter(c).Format(time.RFC3339)},
		{"is_expired", strconv.FormatBool(IsExpired(c, now))},
		{"key_algorithm", KeyAlgorithm(c)},
		{"signature_algorithm", SignatureAlgorithm(c)},
		{"fingerprint_sha256", Fingerprint(c)},
		{"is_ca", strconv.FormatBool(IsCA(c))},
		{"sans", strings.Join(SANs(c), ",")},
	}
}
