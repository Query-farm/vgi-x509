// Copyright 2026 Query Farm LLC - https://query.farm

// Package testca generates deterministic-shape self-signed X.509 certificates
// for tests and the mock TLS server. It is NOT a production CA — it exists only
// so the parsing scalars and tls_inspect have a known certificate to assert
// against without reaching the public internet.
package testca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// CertSpec controls the generated certificate.
type CertSpec struct {
	CommonName   string
	Organization string
	DNSNames     []string
	IPAddresses  []net.IP
	NotBefore    time.Time
	NotAfter     time.Time
	IsCA         bool
	Serial       int64
}

// Generated bundles the artifacts of a generated self-signed certificate.
type Generated struct {
	Cert    *x509.Certificate
	DER     []byte
	PEM     []byte
	KeyPEM  []byte
	TLSCert tls.Certificate
}

// Default returns a CertSpec for a typical valid leaf certificate: CN=example
// test, SANs example.com / *.example.com / 127.0.0.1, valid from one hour ago
// to one year out.
func Default() CertSpec {
	now := time.Now()
	return CertSpec{
		CommonName:   "example.test",
		Organization: "VGI X509 Test",
		DNSNames:     []string{"example.test", "www.example.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		IsCA:         false,
		Serial:       4242,
	}
}

// Generate builds a self-signed ECDSA-P256 certificate from spec.
func Generate(spec CertSpec) (*Generated, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(spec.Serial),
		Subject: pkix.Name{
			CommonName:   spec.CommonName,
			Organization: []string{spec.Organization},
		},
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  spec.IsCA,
		DNSNames:              spec.DNSNames,
		IPAddresses:           spec.IPAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &Generated{
		Cert:    cert,
		DER:     der,
		PEM:     certPEM,
		KeyPEM:  keyPEM,
		TLSCert: tlsCert,
	}, nil
}
