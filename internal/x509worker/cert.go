// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// This file implements the pure, offline X.509 parsing surface: no network,
// fully deterministic, and the easiest part of the worker to test. Every cert
// scalar is a thin wrapper over ParseCertificate plus one accessor here.
//
// PEM-vs-DER dispatch: a certificate may arrive either as a PEM text string
// (VARCHAR) or as raw DER bytes (BLOB). ParseCertificate sniffs the input —
// if it begins with the PEM armor "-----BEGIN", it is decoded as PEM; otherwise
// it is treated as DER. This lets one code path serve both SQL input types.

// ParseCertificate parses a certificate supplied as either PEM text or raw DER
// bytes. It returns a clear error for malformed input so callers can surface a
// clean SQL error (or map to NULL) rather than crashing.
func ParseCertificate(raw []byte) (*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("x509: empty certificate input")
	}

	der := raw
	// Sniff for PEM armor. We trim leading whitespace because callers often
	// embed certs with a leading newline.
	trimmed := strings.TrimLeft(string(raw), " \t\r\n")
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, fmt.Errorf("x509: input looks like PEM but no PEM block could be decoded")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("x509: PEM block type is %q, expected CERTIFICATE", block.Type)
		}
		der = block.Bytes
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("x509: failed to parse certificate: %w", err)
	}
	return cert, nil
}

// Subject returns the certificate subject as an RFC 2253 distinguished name.
func Subject(c *x509.Certificate) string { return c.Subject.String() }

// Issuer returns the certificate issuer as an RFC 2253 distinguished name.
func Issuer(c *x509.Certificate) string { return c.Issuer.String() }

// Serial returns the certificate serial number as a base-10 string. Serial
// numbers can exceed 64 bits, so a decimal string is the safe representation.
func Serial(c *x509.Certificate) string { return c.SerialNumber.String() }

// NotBefore returns the start of the certificate validity window (UTC).
func NotBefore(c *x509.Certificate) time.Time { return c.NotBefore.UTC() }

// NotAfter returns the end of the certificate validity window (UTC).
func NotAfter(c *x509.Certificate) time.Time { return c.NotAfter.UTC() }

// IsExpired reports whether the certificate is outside its validity window at
// time now (either not yet valid or already expired).
func IsExpired(c *x509.Certificate, now time.Time) bool {
	return now.Before(c.NotBefore) || now.After(c.NotAfter)
}

// IsCA reports whether the certificate is a CA certificate (BasicConstraints).
func IsCA(c *x509.Certificate) bool { return c.IsCA }

// UnknownAlgorithm is what KeyAlgorithm and SignatureAlgorithm return for an
// algorithm Go's crypto/x509 does not recognise. Without it Go's String()
// methods render the zero enum value as the bare string "0".
const UnknownAlgorithm = "Unknown"

// KeyAlgorithm returns a human-readable public-key algorithm with key size or
// curve, e.g. "RSA-2048", "ECDSA-P256", "Ed25519", "X25519", or UnknownAlgorithm.
func KeyAlgorithm(c *x509.Certificate) string {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		name := pub.Curve.Params().Name // e.g. "P-256"
		return "ECDSA-" + strings.ReplaceAll(name, "-", "")
	case ed25519.PublicKey:
		return "Ed25519"
	}
	if c.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		// crypto/x509 leaves PublicKey nil for algorithms it does not model,
		// including the RFC 8410 curves other than Ed25519, so name those from
		// the SubjectPublicKeyInfo OID.
		var spki struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err == nil {
			for oid, name := range rfc8410Keys {
				if spki.Algorithm.Algorithm.String() == oid {
					return name
				}
			}
		}
		return UnknownAlgorithm
	}
	return c.PublicKeyAlgorithm.String()
}

// rfc8410Keys names the RFC 8410 key OIDs that crypto/x509 reports as unknown.
var rfc8410Keys = map[string]string{
	"1.3.101.110": "X25519",
	"1.3.101.111": "X448",
	"1.3.101.113": "Ed448",
}

// SignatureAlgorithm returns the certificate signature algorithm name, e.g.
// "SHA256-RSA", "ECDSA-SHA256", or UnknownAlgorithm for an unrecognised OID.
func SignatureAlgorithm(c *x509.Certificate) string {
	if c.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return UnknownAlgorithm
	}
	return c.SignatureAlgorithm.String()
}

// Fingerprint returns the SHA-256 fingerprint of the DER certificate as a
// lowercase hex string (no colons), which is stable for a given certificate.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// SANs returns the certificate subject alternative names: DNS names first
// (sorted as stored), then IP addresses rendered as strings. URI and email
// SANs are omitted to keep the surface to the "DNS + IP" contract.
func SANs(c *x509.Certificate) []string {
	out := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses))
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}
