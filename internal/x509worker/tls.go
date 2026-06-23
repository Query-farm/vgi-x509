// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// This file implements TLS endpoint inspection. It connects to a host:port,
// completes a TLS handshake, and returns the certificate chain the server
// presented. It is a DEFENSIVE inspection tool: by default it does NOT verify
// the chain (insecure := true) because the point is to inspect whatever a
// server presents, including expired or self-signed certs. Only point it at
// endpoints you are AUTHORIZED to inspect.

// TLSInspectOptions controls a TLS inspection.
type TLSInspectOptions struct {
	// Timeout bounds the whole dial + handshake. Zero means a 10s default.
	Timeout time.Duration
	// Insecure disables chain verification (the default for inspection).
	Insecure bool
	// ServerName sets SNI. Empty means derive it from the host portion of the
	// address (matching normal client behavior).
	ServerName string
}

// InspectTLS connects to hostPort (e.g. "example.com:443"), performs a TLS
// handshake, and returns the peer certificate chain in presentation order.
// Connection or handshake failures (including timeouts) return a clear error;
// the function never blocks indefinitely.
func InspectTLS(ctx context.Context, hostPort string, opts TLSInspectOptions) ([]*x509.Certificate, error) {
	if hostPort == "" {
		return nil, fmt.Errorf("tls: empty host:port")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("tls: invalid host:port %q: %w", hostPort, err)
	}
	serverName := opts.ServerName
	if serverName == "" {
		serverName = host
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("tls: dial %q: %w", hostPort, err)
	}
	defer func() { _ = rawConn.Close() }()

	// Bound the handshake by the same deadline as the dial.
	deadline, ok := dialCtx.Deadline()
	if ok {
		_ = rawConn.SetDeadline(deadline)
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: opts.Insecure, //nolint:gosec // inspection tool: verification is opt-in
	})
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return nil, fmt.Errorf("tls: handshake with %q failed: %w", hostPort, err)
	}

	chain := tlsConn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, fmt.Errorf("tls: %q presented no certificates", hostPort)
	}
	return chain, nil
}
