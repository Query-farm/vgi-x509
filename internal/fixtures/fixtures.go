// Copyright 2026 Query Farm LLC - https://query.farm

// Package fixtures holds the committed X.509 sample certificates shared by the
// worker's examples and agent tasks (internal/x509worker) and the mock crt.sh
// server (internal/ctmock). They are synthetic: the keys were thrown away and
// nothing here is trusted by anything.
package fixtures

// TestPEM is a self-signed certificate: CN=test.vgi-x509.example,
// O=VGI X509 Fixture, serial 987654321 (hex 3ade68b1), valid 2025-01-01 ..
// 2035-01-01, ECDSA P-256, SANs test.vgi-x509.example / alt.vgi-x509.example /
// 127.0.0.1.
const TestPEM = "-----BEGIN CERTIFICATE-----\n" +
	"MIIB3DCCAYGgAwIBAgIEOt5osTAKBggqhkjOPQQDAjA7MRkwFwYDVQQKExBWR0kg\n" +
	"WDUwOSBGaXh0dXJlMR4wHAYDVQQDExV0ZXN0LnZnaS14NTA5LmV4YW1wbGUwHhcN\n" +
	"MjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA7MRkwFwYDVQQKExBWR0kgWDUw\n" +
	"OSBGaXh0dXJlMR4wHAYDVQQDExV0ZXN0LnZnaS14NTA5LmV4YW1wbGUwWTATBgcq\n" +
	"hkjOPQIBBggqhkjOPQMBBwNCAAS7Zbq+Bz73Y0wKrZZkw4owgz7qyAtXYUrNUkac\n" +
	"Ot2h1WpF/Y+ODgRoeo0+ixbqPxA8+Lm9DTpksjsxTMRni/Owo3MwcTAOBgNVHQ8B\n" +
	"Af8EBAMCAoQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADA8BgNV\n" +
	"HREENTAzghV0ZXN0LnZnaS14NTA5LmV4YW1wbGWCFGFsdC52Z2kteDUwOS5leGFt\n" +
	"cGxlhwR/AAABMAoGCCqGSM49BAMCA0kAMEYCIQCGCty4v7uWVHE/HhanzxE2kzBo\n" +
	"KBiJ1j25vqPbFP4x7AIhAPdzfBNzgiIxriWsiBH1HBtoOCRsMJ6WN+j7zxyn9Np0\n" +
	"-----END CERTIFICATE-----"

// LegacyPEM is the opposite of TestPEM on every policy axis:
// CN=legacy.vgi-x509.example, serial 1001 (hex 03e9), valid 2015-01-01 ..
// 2016-01-01 (expired), RSA-1024, signed with ECDSA-SHA1 by a separate
// "VGI X509 Fixture CA", SAN legacy.vgi-x509.example.
const LegacyPEM = "-----BEGIN CERTIFICATE-----\n" +
	"MIIB0jCCAXigAwIBAgICA+kwCQYHKoZIzj0EATA5MRkwFwYDVQQKExBWR0kgWDUw\n" +
	"OSBGaXh0dXJlMRwwGgYDVQQDExNWR0kgWDUwOSBGaXh0dXJlIENBMB4XDTE1MDEw\n" +
	"MTAwMDAwMFoXDTE2MDEwMTAwMDAwMFowPTEZMBcGA1UEChMQVkdJIFg1MDkgRml4\n" +
	"dHVyZTEgMB4GA1UEAxMXbGVnYWN5LnZnaS14NTA5LmV4YW1wbGUwgZ8wDQYJKoZI\n" +
	"hvcNAQEBBQADgY0AMIGJAoGBAKnXtIZR7d7y/tykoXIu2UFuu6pOM3wTOgeA9REt\n" +
	"a9h+tGfssuxWZ7c8ILquhCxda+A92qlCepAbgh7sfDCoV7X0ST5gzF+YuzXRxgxh\n" +
	"drwhmeFLO9QcuVLF/Xu6japDPQ/eC6E/gaA0+p8vhE98WWC45S34wUPbPjmIEMC0\n" +
	"lr9JAgMBAAGjJjAkMCIGA1UdEQQbMBmCF2xlZ2FjeS52Z2kteDUwOS5leGFtcGxl\n" +
	"MAkGByqGSM49BAEDSQAwRgIhAKsIPC+paKp/9ZycM4y3pUVIFfHc0Kl7OsEuceKa\n" +
	"riO1AiEA1Cd3nEmbffFOBMjt3TmYKYZRo4DskxRqX4I41HUb274=\n" +
	"-----END CERTIFICATE-----"
