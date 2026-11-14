# vgi-x509 Makefile
#
# A VGI worker (Go) that parses X.509 certificates and inspects TLS endpoints,
# exposed as DuckDB SQL functions. Targets:
#
#   make build       Build the worker + mock-TLS-server binaries
#   make test-unit   Run the pure-Go unit tests
#   make test-sql    Run the haybarn-unittest SQL E2E against a local mock TLS server
#                    (TRANSPORT=subprocess|http|unix, default subprocess)
#   make test        test-unit + test-sql
#   make fmt         gofmt -w
#   make vet         go vet
#   make lint        golangci-lint
#   make clean       Remove built binaries
#
# test-sql needs haybarn-unittest on PATH:
#   uv tool install --prerelease allow 'haybarn-unittest>=2.0.0rc11,<2.1'
#   export PATH="$$HOME/.local/bin:$$PATH"

WORKER_BIN  := vgi-x509-worker
MOCK_BIN    := mockserver
WORKER_CMD  := ./cmd/vgi-x509-worker
MOCK_CMD    := ./cmd/mockserver

TRANSPORT ?= subprocess

# Absolute path to the built worker (the VGI extension launches it via LOCATION).
WORKER_PATH := $(CURDIR)/$(WORKER_BIN)

.PHONY: build test test-unit test-sql fmt vet lint clean

build:
	go build -o $(WORKER_BIN) $(WORKER_CMD)
	go build -o $(MOCK_BIN) $(MOCK_CMD)

test: test-unit test-sql

test-unit:
	go test ./...

# Build the worker and run the SQL suite through ci/run-integration.sh, the
# same script CI runs: it builds + starts the mock TLS server, stages the tests,
# runs haybarn-unittest (2.0, with --keep-home) and fails if every test was
# skipped. TRANSPORT=http|unix selects another worker transport.
test-sql: build
	HAYBARN_UNITTEST="$$(command -v haybarn-unittest)" \
	VGI_X509_WORKER="$(WORKER_PATH)" \
	TRANSPORT="$(TRANSPORT)" \
		ci/run-integration.sh

fmt:
	gofmt -w .

vet:
	go vet ./...

lint:
	golangci-lint run

clean:
	rm -f $(WORKER_BIN) $(MOCK_BIN)
