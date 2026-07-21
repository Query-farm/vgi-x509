# Copyright 2026 Query Farm LLC - https://query.farm
#
# Single image that serves the network transports of the `vgi-x509` VGI worker:
#   docker run ... IMG            -> HTTP server on $PORT       (default; Fly.io / local)
#   docker run -i ... IMG stdio   -> stdio worker DuckDB spawns on-host
#   docker run ... IMG unix       -> AF_UNIX launcher transport on $UNIX_SOCK
# See docker-entrypoint.sh.
#
# The worker is STATELESS: it parses the X.509 certificate / inspects the TLS
# endpoint given in each call (Go stdlib crypto/x509 + crypto/tls), so there is
# no /data volume and no `farm.query.vgi.volumes` mount-discovery label.
# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------------
# CGO is required: the vgi-go SDK links DuckDB (via duckdb/duckdb-go), so
# CGO_ENABLED=0 fails to build. gcc/g++ back the cgo link. Pinned glibc
# (bookworm) so the binary links against the same libc the slim runtime ships.
FROM golang:1.26-bookworm AS build
WORKDIR /src

ENV CGO_ENABLED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc g++ libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Resolve modules first (cached across source-only changes). No `replace`
# directives in go.mod, so a plain `go mod download` fetches everything.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY cmd ./cmd
COPY internal ./internal

# BuildKit cache mounts persist the module + build caches across image
# rebuilds, so incremental code changes only recompile the changed packages
# and the cgo link. The worker main package is ./cmd/vgi-x509-worker.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /worker ./cmd/vgi-x509-worker

# ---- runtime stage ---------------------------------------------------------
# debian-slim (not distroless) so the HEALTHCHECK below has a real `curl`.
FROM debian:bookworm-slim

# Build metadata, wired from docker/metadata-action outputs in CI.
ARG VERSION=0.0.0
ARG GIT_COMMIT=unknown
ARG SOURCE_URL=https://github.com/Query-farm/vgi-x509

# Standard OCI labels + the VGI transport-advertisement label. `transports`
# lists the NETWORK transports this image serves (http); stdio and unix are
# spawn/socket modes, not published network transports, so they are not listed.
LABEL org.opencontainers.image.title="vgi-x509" \
      org.opencontainers.image.description="Parse X.509 certificates and inspect live TLS endpoints as DuckDB SQL functions — a VGI worker (stdio + HTTP + AF_UNIX)" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.licenses="MIT" \
      farm.query.vgi.transports='["http"]'

ENV PORT=8000 \
    # Build provenance only; the version the worker advertises over VGI comes
    # from the compiled catalog metadata, not this.
    VGI_X509_GIT_COMMIT=${GIT_COMMIT}

WORKDIR /app

# curl backs the HEALTHCHECK below; ca-certificates for outbound TLS name
# resolution. tls_inspect uses InsecureSkipVerify (it inspects, not trusts),
# but ca-certificates is cheap and keeps the image well-behaved.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# `--chmod` sets the mode in the COPY layer itself (a separate `RUN chmod`
# would rewrite the whole binary into a second layer).
COPY --from=build --chmod=0755 /worker /usr/local/bin/vgi-x509-worker
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Run unprivileged. No state, no volume — there is nothing to own or persist.
RUN useradd --create-home --uid 10001 app
USER app

EXPOSE 8000

# Readiness probe for HTTP mode. Inert for a short-lived stdio container, which
# has no HTTP server (the probe just fails harmlessly there).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT:-8000}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["http"]
