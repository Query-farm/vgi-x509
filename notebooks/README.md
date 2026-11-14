# VGI X.509 notebooks

[01 · Plan certificate work without losing the denominator](01_plan_certificate_work.ipynb) parses synthetic certificate files with visible SQL, audits validity windows at a fixed UTC assessment time, and compares assignment counts with distinct certificate fingerprints. It keeps missing, expired and not-yet-valid certificates separate.

## Run

Install [uv](https://docs.astral.sh/uv/). From the repository root:

```sh
uv sync --project notebooks --frozen
uv run --project notebooks --frozen python notebooks/execute.py
```

The entire `notebooks/` directory also runs outside the worker checkout:

```sh
cd notebooks
uv sync --frozen
uv run --frozen python execute.py
```

Initial setup needs network access for the Python environment, VGI community extension and pinned native worker release. Certificate analysis is offline. No Go toolchain, worker build, credentials, live endpoints or external dataset is needed. Native archives cover macOS Apple silicon, Linux x86-64/arm64 and Windows x86-64; execution was verified on macOS Apple silicon.

In VS Code select `notebooks/.venv/bin/python` and use `notebooks/` as the kernel working directory. Other Jupyter editors can register the kernel:

```sh
uv run --project notebooks --frozen python -m ipykernel install --user --name vgi-x509-notebooks --display-name 'Python (vgi-x509 notebooks)'
```

Restart and run all after changing parameters. VGI connection and analytical SQL remain visible; imports, styling, plots, assertions and cleanup source are folded. Both charts are embedded in the saved notebook.

## Experiment

```sh
uv run --project notebooks --frozen python notebooks/execute.py \
  --parameters '{"HORIZON_DAYS":60}' \
  --output-dir notebooks/validation/horizon-60
```

The default horizon is 14 days; the experiment widens it to 60. The assessment remains 2026-01-01 00:00:00 UTC. The runner requires a separate output directory for overrides, rejects unknown names, and saves only successful full executions. Failed runs preserve prior saved notebooks. Copies include relative assets, fixtures, helpers, environment and this documentation. Generated review charts, logs and experiment copies are ignored.

## Portable startup and synthetic fixtures

The literal SQL location is `github-auto://Query-farm/vgi-x509@v0.4.0`. VGI downloads, verifies and caches the platform release. The notebook lock pins Haybarn 2.0.0rc11; change the worker tag explicitly to upgrade and rerun both settings.

Six authored Ed25519 leaf certificates are committed in PEM and DER form under `fixtures/`. The public `.example` names describe synthetic records. Two assignments share `shared-soon`, and one assignment has no certificate. The fixture intervals, expressed as days relative to the fixed assessment, are:

| Certificate | NotBefore | NotAfter |
| --- | ---: | ---: |
| expired | −60 | −10 |
| shared-soon | −30 | +7 |
| boundary | −30 | +14 |
| later | −30 | +45 |
| future | +10 | +90 |
| long | −30 | +120 |

`build_fixtures.go` uses only the Go standard library and deterministic test keys to generate these exact certificate bytes. No private key file is saved. The keys are derivable from public fixture text and must never be used in service. Notebook execution uses the committed files and does not run the generator. Optional regeneration, with Go installed:

```sh
go run notebooks/build_fixtures.go /tmp/vgi-x509-fixtures
```

Regeneration was checked byte-for-byte against all twelve committed files. Each PEM file contains one certificate; the notebook is not a PEM-bundle inventory parser. Certificate SHA-256 fingerprints match both PEM/DER representations and SQL hashes of the original DER bytes.

## Time and interpretation

Worker timestamps represent UTC wall-clock time as plain SQL TIMESTAMP. The notebook compares them with the explicit UTC assessment timestamp. It avoids `cert_is_expired`, whose answer follows the current clock and includes both expired and not-yet-valid certificates. The planning policy includes currently time-valid certificates with NotAfter at or before the horizon; the boundary certificate verifies the inclusive comparison.

The inventory has eight assignment rows and six distinct observed certificate fingerprints. Missing material remains unknown, not valid or expired. Counting assignments answers a different question from counting certificate bytes. A shared certificate appears once in the certificate-level work list with its assignment list retained.

Parsing does not validate a trust chain, check revocation, verify DNS names or establish what a server presents. Subject/issuer equality means self-issued; it does not itself verify the signature. The fixture generator establishes that these particular certificates were self-signed. The notebook does not invoke `tls_inspect` or contact live TLS endpoints. Repository transport tests exercise TLS inspection against disposable loopback servers.

Malformed certificate bytes fail parsing; SQL NULL propagates NULL. The notebook checks both separately, so malformed input is not silently converted into missing data. It does not assert current browser certificate policies or production compliance.

Validation covers both parameter settings, detached notebook execution, four chart renderings, twelve SQL checks, count reconciliations, a malformed-input probe and three runner guards. The polished default took 1.7 seconds and the detached sixty-day experiment took 1.9 seconds. The planning set grows from 3 to 4 assignments and from 2 to 3 distinct certificates; parsed certificate output remains identical. Source validation passed 29 Go tests, 71 stdio / 77 HTTP / 71 Unix SQL assertions (three cases per transport), build, vet, gofmt and golangci-lint. Metadata scored 100/100 L1 with zero findings. Metadata is checked structurally with example execution disabled because the repository's metadata examples include an external TLS endpoint; the actual offline parsing and loopback TLS behavior are covered by the notebook and repository SQL suites. Source code, tests, Go manifests and checksums remain unchanged.

Official Query.Farm Strata Sun and VGI artwork is copied unchanged from the approved assets, with linked Query.Farm branding at the top and bottom.
