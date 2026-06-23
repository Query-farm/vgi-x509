// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/Query-farm/vgi-x509/internal/testca"
)

// startTLSServer starts an in-process TLS server presenting cert g and returns
// its host:port. The server closes connections right after the handshake.
func startTLSServer(t *testing.T, g *testca.Generated) string {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{g.TLSCert}}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_ = c.Close()
			}(conn)
		}
	}()
	return lis.Addr().String()
}

func TestInspectTLS(t *testing.T) {
	g := mustGen(t, func(s *testca.CertSpec) {
		s.CommonName = "inspect.example"
		s.DNSNames = []string{"inspect.example"}
	})
	addr := startTLSServer(t, g)

	chain, err := InspectTLS(context.Background(), addr, TLSInspectOptions{
		Insecure: true,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("InspectTLS: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("chain length = %d, want 1", len(chain))
	}
	leaf := chain[0]
	if Subject(leaf) != Subject(g.Cert) {
		t.Errorf("subject = %q, want %q", Subject(leaf), Subject(g.Cert))
	}
	if Fingerprint(leaf) != Fingerprint(g.Cert) {
		t.Errorf("fingerprint = %q, want %q", Fingerprint(leaf), Fingerprint(g.Cert))
	}
}

func TestInspectTLSUnreachable(t *testing.T) {
	// Port 1 on localhost is essentially never listening; a short timeout keeps
	// the test fast and asserts we surface a clean error rather than hang.
	_, err := InspectTLS(context.Background(), "127.0.0.1:1", TLSInspectOptions{
		Insecure: true,
		Timeout:  2 * time.Second,
	})
	if err == nil {
		t.Errorf("InspectTLS to unreachable host: expected error, got nil")
	}
}

func TestInspectTLSBadAddr(t *testing.T) {
	if _, err := InspectTLS(context.Background(), "not-a-host-port", TLSInspectOptions{Insecure: true}); err == nil {
		t.Errorf("InspectTLS with malformed addr: expected error, got nil")
	}
	if _, err := InspectTLS(context.Background(), "", TLSInspectOptions{Insecure: true}); err == nil {
		t.Errorf("InspectTLS with empty addr: expected error, got nil")
	}
}
