// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// The second committed fixture is an RSA-1024 leaf signed with ECDSA-SHA1 by a
// separate (uncommitted) CA, so it exercises the RSA and legacy-signature paths.
func TestLegacyFixtureAlgorithms(t *testing.T) {
	c, err := ParseCertificate([]byte(legacyPEM))
	if err != nil {
		t.Fatalf("parse legacy fixture: %v", err)
	}
	if got := KeyAlgorithm(c); got != "RSA-1024" {
		t.Errorf("KeyAlgorithm = %q, want RSA-1024", got)
	}
	if got := SignatureAlgorithm(c); got != "ECDSA-SHA1" {
		t.Errorf("SignatureAlgorithm = %q, want ECDSA-SHA1", got)
	}
	if got := Serial(c); got != "1001" {
		t.Errorf("Serial = %q, want 1001", got)
	}
	if Subject(c) == Issuer(c) {
		t.Errorf("legacy fixture should be CA-issued, got issuer == subject %q", Subject(c))
	}
}

// crypto/x509 reports an X25519 subject key as UnknownPublicKeyAlgorithm (with a
// nil PublicKey), whose String() is "0". KeyAlgorithm must name it instead. CreateCertificate cannot
// embed an X25519 key, so build an Ed25519-keyed certificate and swap the SPKI
// OID 1.3.101.112 (Ed25519) for 1.3.101.110 (X25519): both are 32-byte keys
// with the same encoding length.
func TestKeyAlgorithmX25519(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "x25519.test"},
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, leafPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	der = replaceAll(t, der,
		[]byte{0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00},
		[]byte{0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00})
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if got := KeyAlgorithm(c); got != "X25519" {
		t.Errorf("KeyAlgorithm = %q, want X25519", got)
	}
}

// replaceAll swaps every occurrence of old in b, failing if there is none.
func replaceAll(t *testing.T, b, old, repl []byte) []byte {
	t.Helper()
	if !bytes.Contains(b, old) {
		t.Fatalf("pattern %x not found", old)
	}
	return bytes.ReplaceAll(b, old, repl)
}

// An unrecognised signature or public-key OID must render as "Unknown", not
// as Go's bare enum number "0".
func TestUnknownAlgorithms(t *testing.T) {
	block, _ := pem.Decode([]byte(fixturePEM))
	if block == nil {
		t.Fatal("decode fixture")
	}
	// ecdsa-with-SHA256 (1.2.840.10045.4.3.2) -> 1.2.840.10045.4.3.9, which Go
	// does not know. It appears twice (TBS + outer), and both must match.
	sigOID := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}
	unkSig := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x09}
	der := replaceAll(t, block.Bytes, sigOID, unkSig)
	// id-ecPublicKey (1.2.840.10045.2.1) -> 1.2.840.10045.2.9.
	keyOID := []byte{0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01}
	unkKey := []byte{0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x09}
	der = replaceAll(t, der, keyOID, unkKey)

	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse mutated fixture: %v", err)
	}
	if got := SignatureAlgorithm(c); got != UnknownAlgorithm {
		t.Errorf("SignatureAlgorithm = %q, want %q", got, UnknownAlgorithm)
	}
	if got := KeyAlgorithm(c); got != UnknownAlgorithm {
		t.Errorf("KeyAlgorithm = %q, want %q", got, UnknownAlgorithm)
	}
}
