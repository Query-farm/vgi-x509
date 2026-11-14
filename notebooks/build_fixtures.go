// Build deterministic, synthetic certificate fixtures; never use these keys in service.
// Run: go run build_fixtures.go /path/to/output
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		panic("supply the output directory")
	}
	out := os.Args[1]
	if err := os.MkdirAll(out, 0755); err != nil {
		panic(err)
	}
	assessment := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixtures := []struct {
		name       string
		start, end int
	}{
		{"expired", -60, -10}, {"shared-soon", -30, 7},
		{"boundary", -30, 14}, {"later", -30, 45},
		{"future", 10, 90}, {"long", -30, 120},
	}
	for i, f := range fixtures {
		seed := sha256.Sum256([]byte("VGI X509 synthetic notebook key: " + f.name))
		key := ed25519.NewKeyFromSeed(seed[:])
		cert := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(1001 + i)),
			Subject:               pkix.Name{CommonName: f.name + ".example", Organization: []string{"Synthetic notebook fixture"}},
			NotBefore:             assessment.Add(time.Duration(f.start) * 24 * time.Hour),
			NotAfter:              assessment.Add(time.Duration(f.end) * 24 * time.Hour),
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:              []string{f.name + ".example"},
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
		if err != nil {
			panic(err)
		}
		for extension, contents := range map[string][]byte{
			"der": der,
			"pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		} {
			if err := os.WriteFile(filepath.Join(out, f.name+"."+extension), contents, 0644); err != nil {
				panic(err)
			}
		}
		fmt.Println(f.name)
	}
}
