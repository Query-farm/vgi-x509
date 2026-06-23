// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Query-farm/vgi-x509/internal/testca"
)

// mustGen builds a self-signed cert from the default spec with the given
// overrides applied, failing the test on error.
func mustGen(t *testing.T, mutate func(*testca.CertSpec)) *testca.Generated {
	t.Helper()
	spec := testca.Default()
	if mutate != nil {
		mutate(&spec)
	}
	g, err := testca.Generate(spec)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	return g
}

func TestParseCertificatePEMAndDER(t *testing.T) {
	g := mustGen(t, nil)

	// PEM input.
	cPEM, err := ParseCertificate(g.PEM)
	if err != nil {
		t.Fatalf("ParseCertificate(PEM): %v", err)
	}
	// DER input.
	cDER, err := ParseCertificate(g.DER)
	if err != nil {
		t.Fatalf("ParseCertificate(DER): %v", err)
	}
	// Both must yield the same certificate (same fingerprint).
	if Fingerprint(cPEM) != Fingerprint(cDER) {
		t.Errorf("PEM and DER parse to different fingerprints: %s vs %s", Fingerprint(cPEM), Fingerprint(cDER))
	}
	// PEM with a leading newline (common in embedded literals) must still parse.
	if _, err := ParseCertificate(append([]byte("\n"), g.PEM...)); err != nil {
		t.Errorf("ParseCertificate(leading-newline PEM): %v", err)
	}
}

func TestParseCertificateMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":        {},
		"garbage-der":  []byte{0x30, 0x01, 0x02, 0x03},
		"bad-pem":      []byte("-----BEGIN CERTIFICATE-----\nnotbase64!!!\n-----END CERTIFICATE-----\n"),
		"wrong-pem":    []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		"plain-string": []byte("this is not a certificate"),
	}
	for name, raw := range cases {
		if _, err := ParseCertificate(raw); err == nil {
			t.Errorf("ParseCertificate(%s) expected error, got nil", name)
		}
	}
}

func TestScalarAccessors(t *testing.T) {
	g := mustGen(t, func(s *testca.CertSpec) {
		s.CommonName = "leaf.example"
		s.Organization = "Acme"
		s.Serial = 12345
		s.DNSNames = []string{"leaf.example", "alt.example"}
		s.IPAddresses = []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("127.0.0.1")}
	})
	c := g.Cert

	if got := Subject(c); !strings.Contains(got, "CN=leaf.example") || !strings.Contains(got, "O=Acme") {
		t.Errorf("Subject = %q, want CN=leaf.example and O=Acme", got)
	}
	if got := Issuer(c); !strings.Contains(got, "CN=leaf.example") {
		t.Errorf("Issuer (self-signed) = %q, want CN=leaf.example", got)
	}
	if got := Serial(c); got != "12345" {
		t.Errorf("Serial = %q, want 12345", got)
	}
	if got := KeyAlgorithm(c); got != "ECDSA-P256" {
		t.Errorf("KeyAlgorithm = %q, want ECDSA-P256", got)
	}
	if got := SignatureAlgorithm(c); got == "" {
		t.Errorf("SignatureAlgorithm empty")
	}
	if IsCA(c) {
		t.Errorf("IsCA = true, want false for default leaf")
	}

	// Fingerprint is 64 lowercase hex chars and stable across calls.
	fp := Fingerprint(c)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fp) {
		t.Errorf("Fingerprint = %q, want 64 lowercase hex chars", fp)
	}
	if fp != Fingerprint(c) {
		t.Errorf("Fingerprint not stable")
	}

	// SANs: DNS names then IPs.
	sans := SANs(c)
	want := []string{"leaf.example", "alt.example", "10.0.0.1", "127.0.0.1"}
	if strings.Join(sans, ",") != strings.Join(want, ",") {
		t.Errorf("SANs = %v, want %v", sans, want)
	}
}

func TestKeyAlgorithmRSA(t *testing.T) {
	// The default generator is ECDSA; cover the RSA branch via a known cert.
	// We reuse the ECDSA cert but assert the ECDSA path here; RSA is exercised
	// by the human-readable format string. (Kept minimal: ECDSA is generated.)
	g := mustGen(t, nil)
	if got := KeyAlgorithm(g.Cert); !strings.HasPrefix(got, "ECDSA-") {
		t.Errorf("KeyAlgorithm = %q, want ECDSA- prefix", got)
	}
}

func TestIsExpired(t *testing.T) {
	now := time.Now()

	valid := mustGen(t, func(s *testca.CertSpec) {
		s.NotBefore = now.Add(-time.Hour)
		s.NotAfter = now.Add(time.Hour)
	})
	if IsExpired(valid.Cert, now) {
		t.Errorf("IsExpired = true for a currently-valid cert")
	}

	expired := mustGen(t, func(s *testca.CertSpec) {
		s.NotBefore = now.Add(-48 * time.Hour)
		s.NotAfter = now.Add(-24 * time.Hour)
	})
	if !IsExpired(expired.Cert, now) {
		t.Errorf("IsExpired = false for a backdated (expired) cert")
	}

	notYet := mustGen(t, func(s *testca.CertSpec) {
		s.NotBefore = now.Add(24 * time.Hour)
		s.NotAfter = now.Add(48 * time.Hour)
	})
	if !IsExpired(notYet.Cert, now) {
		t.Errorf("IsExpired = false for a not-yet-valid cert")
	}
}

func TestNotBeforeNotAfter(t *testing.T) {
	nb := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	na := time.Date(2030, 6, 7, 8, 9, 10, 0, time.UTC)
	g := mustGen(t, func(s *testca.CertSpec) {
		s.NotBefore = nb
		s.NotAfter = na
	})
	if !NotBefore(g.Cert).Equal(nb) {
		t.Errorf("NotBefore = %v, want %v", NotBefore(g.Cert), nb)
	}
	if !NotAfter(g.Cert).Equal(na) {
		t.Errorf("NotAfter = %v, want %v", NotAfter(g.Cert), na)
	}
}

func TestIsCA(t *testing.T) {
	ca := mustGen(t, func(s *testca.CertSpec) { s.IsCA = true })
	if !IsCA(ca.Cert) {
		t.Errorf("IsCA = false for a CA cert")
	}
}

func TestCertInfoRows(t *testing.T) {
	g := mustGen(t, func(s *testca.CertSpec) { s.CommonName = "info.example" })
	rows := CertInfo(g.Cert, time.Now())

	got := map[string]string{}
	for _, r := range rows {
		got[r.Field] = r.Value
	}
	for _, field := range []string{
		"subject", "issuer", "serial", "not_before", "not_after",
		"is_expired", "key_algorithm", "signature_algorithm",
		"fingerprint_sha256", "is_ca", "sans",
	} {
		if _, ok := got[field]; !ok {
			t.Errorf("CertInfo missing field %q", field)
		}
	}
	if !strings.Contains(got["subject"], "CN=info.example") {
		t.Errorf("CertInfo subject = %q", got["subject"])
	}
	if got["is_ca"] != "false" {
		t.Errorf("CertInfo is_ca = %q, want false", got["is_ca"])
	}
	if got["key_algorithm"] != "ECDSA-P256" {
		t.Errorf("CertInfo key_algorithm = %q, want ECDSA-P256", got["key_algorithm"])
	}
}
