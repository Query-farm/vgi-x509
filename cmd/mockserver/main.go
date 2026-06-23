// Copyright 2026 Query Farm LLC - https://query.farm

// Command mockserver runs a standalone TLS server presenting a generated
// self-signed certificate. It is used by the haybarn SQL end-to-end tests: the
// Makefile starts it on a free port, reads the printed PORT line, and points
// the worker's tls_inspect function at 127.0.0.1:<port>.
//
// Usage:
//
//	mockserver [--addr 127.0.0.1:0]
//
// On startup it prints "PORT:<n>" (the bound TCP port) and "CN:<commonName>"
// (the certificate subject CN) to stdout so a caller can discover both even
// when binding to :0.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Query-farm/vgi-x509/internal/testca"
)

// mockCN is the fixed subject Common Name the mock TLS server presents, so the
// SQL tests can assert tls_inspect returned this exact certificate.
const mockCN = "mock.tls.local"

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "TCP address to listen on (host:port; port 0 = pick a free port)")
	flag.Parse()

	spec := testca.Default()
	spec.CommonName = mockCN
	spec.DNSNames = []string{mockCN}
	gen, err := testca.Generate(spec)
	if err != nil {
		log.Fatalf("mockserver: generate cert: %v", err)
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{gen.TLSCert}}
	lis, err := tls.Listen("tcp", *addr, cfg)
	if err != nil {
		log.Fatalf("mockserver: listen %q: %v", *addr, err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	fmt.Printf("PORT:%d\n", port)
	fmt.Printf("CN:%s\n", mockCN)
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
