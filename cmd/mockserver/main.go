// Copyright 2026 Query Farm LLC - https://query.farm

// Command mockserver runs the offline backends for the haybarn SQL end-to-end
// tests:
//
//   - a TLS server presenting a generated self-signed certificate, which the
//     worker's tls_inspect is pointed at (127.0.0.1:<PORT>);
//   - a plain-HTTP mock of the crt.sh Certificate Transparency API
//     (internal/ctsample), which ct_search / ct_certificate are pointed at with
//     base_url := 'http://127.0.0.1:<CT_PORT>/'.
//
// Usage:
//
//	mockserver [--addr 127.0.0.1:0] [--ct-addr 127.0.0.1:0] [--cert-out <path>]
//
// On startup it prints "PORT:<n>" (the TLS port), "CN:<commonName>" (the TLS
// certificate subject CN) and "CT_PORT:<n>" (the crt.sh mock port) to stdout so
// a caller can discover them even when binding to :0. With --cert-out it also writes the certificate it
// presents as PEM to <path>, so a test can check that tls_inspect's fingerprint
// equals cert_fingerprint over the same certificate (a positive pin match).
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Query-farm/vgi-x509/internal/ctsample"
	"github.com/Query-farm/vgi-x509/internal/testca"
)

// mockCN is the fixed subject Common Name the mock TLS server presents, so the
// SQL tests can assert tls_inspect returned this exact certificate.
const mockCN = "mock.tls.local"

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "TCP address to listen on (host:port; port 0 = pick a free port)")
	certOut := flag.String("cert-out", "", "Write the presented certificate as PEM to this path")
	ctAddr := flag.String("ct-addr", "127.0.0.1:0", "TCP address for the mock crt.sh HTTP API")
	flag.Parse()

	ctLis, err := net.Listen("tcp", *ctAddr)
	if err != nil {
		log.Fatalf("mockserver: listen %q: %v", *ctAddr, err)
	}
	go func() {
		srv := &http.Server{Handler: &ctsample.Handler{}, ReadHeaderTimeout: 10 * time.Second}
		_ = srv.Serve(ctLis)
	}()

	spec := testca.Default()
	spec.CommonName = mockCN
	spec.DNSNames = []string{mockCN}
	gen, err := testca.Generate(spec)
	if err != nil {
		log.Fatalf("mockserver: generate cert: %v", err)
	}

	if *certOut != "" {
		if err := os.WriteFile(*certOut, gen.PEM, 0o644); err != nil { //nolint:gosec // public certificate, not a secret
			log.Fatalf("mockserver: write %q: %v", *certOut, err)
		}
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{gen.TLSCert}}
	lis, err := tls.Listen("tcp", *addr, cfg)
	if err != nil {
		log.Fatalf("mockserver: listen %q: %v", *addr, err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	fmt.Printf("PORT:%d\n", port)
	fmt.Printf("CN:%s\n", mockCN)
	fmt.Printf("CT_PORT:%d\n", ctLis.Addr().(*net.TCPAddr).Port)
	_ = os.Stdout.Sync()

	// Graceful shutdown on SIGINT/SIGTERM so the Makefile's `kill` is clean.
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		_ = lis.Close()
		os.Exit(0)
	}()

	// Accept TLS connections and immediately close them after the handshake.
	// tls_inspect only needs the certificate, which is presented during the
	// handshake, so we don't need to serve any application data.
	for {
		conn, err := lis.Accept()
		if err != nil {
			return // listener closed
		}
		go func(c net.Conn) {
			if tc, ok := c.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = c.Close()
		}(conn)
	}
}
