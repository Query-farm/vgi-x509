# Offline X.509 certificate planning

[01 · Plan certificate work without losing the denominator](01_plan_certificate_work.ipynb)
parses six synthetic certificates through the real worker and joins them to eight
authored assignments. The fixed assessment time is **2026-01-01 00:00:00 UTC**.
The story keeps expired, future and missing material separate, interprets the
certificate profiles, and deduplicates the planning work by certificate fingerprint.

[Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-x509/blob/main/notebooks/01_plan_certificate_work.ipynb)
and run all. The base-only bootstrap uses the
[shared notebook package v0.3.7](https://github.com/Query-farm/vgi-example-notebooks/tree/v0.3.7),
which owns canonical branding, SVG presentation, hash-verified fixture retrieval
and the [standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.7/docs/standard.md).
Saved GitHub charts link to committed SVGs; Jupyter and Colab runs display native SVG.

## Run locally

Install Git and [uv](https://docs.astral.sh/uv/). From this directory:

```sh
uv sync --locked
uv run --locked vgi-notebooks 01_plan_certificate_work.ipynb --timeout 300
```

Select `notebooks/.venv/bin/python` in a Jupyter editor, restart the kernel, and run
all. The local lock adds the shared `[runner]` extra; Colab installs only the base
package, preserving compatible preinstalled plotting and Jupyter libraries.

The visible SQL launches the native published release:

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'x509' (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-x509@v0.4.0');
```

VGI downloads and verifies the platform release. No Go compiler, worker checkout,
credentials or engine build is required. The notebook locks Haybarn 2.0.0rc11.
Initial downloads require network access; the certificate analysis is offline and
makes no TLS endpoint connections. The shared connection uses an empty temporary
SQL-secret directory with persistent secrets disabled. Change the worker release
explicitly when upgrading, then rerun the default and experiment.

## Experiment

Widen the planning horizon from 14 to 60 days in a separate output directory:

```sh
uv run --locked vgi-notebooks 01_plan_certificate_work.ipynb \
  --parameters '{"HORIZON_DAYS":60}' \
  --output-dir artifacts/horizon-60 --timeout 300
```

The `later` certificate and its `batch-service` assignment enter the list. The
selected population grows from **3 to 4 assignments** and **2 to 3 distinct
certificates**. Assessment time, parsed dates, profiles and fingerprints remain
fixed, as do expired, future and missing states. The shared certificate still
represents two assignments. A wider horizon changes planning scope, not validity
or trust. Reset the parameter to 14 for the saved default.

Overrides require a separate destination; failed execution preserves the previous
successful default. Review artifacts, logs and experiment copies are ignored.
A notebook-only copy can retrieve all companions through its bootstrap, without
manual cloning or a local helper module.

## Synthetic fixture provenance

Six authored Ed25519 leaf certificates are committed as PEM and DER under
`fixtures/`. The shared `x509` registry pins their SHA-256 hashes to public commit
`6f0e8893f5c461f112d2076450869c1bff776475`. The `.example` names are synthetic;
no private key is saved. These keys are deterministically derivable from public
fixture text and must never be used in service.

| Certificate | NotBefore, days from assessment | NotAfter, days from assessment |
| --- | ---: | ---: |
| expired | −60 | −10 |
| shared-soon | −30 | +7 |
| boundary | −30 | +14 |
| later | −30 | +45 |
| future | +10 | +90 |
| long | −30 | +120 |

The optional standard-library Go generator reproduces all twelve files byte for
byte. Notebook execution reads the committed files and does not invoke it:

```sh
go run build_fixtures.go /tmp/vgi-x509-fixtures
```

Each PEM contains exactly one certificate. This is not a PEM-bundle inventory
parser. Worker fingerprints match both representations and SQL's SHA-256 of the
original DER bytes. Two assignments share `shared-soon`; one has no certificate
on file. The denominator remains eight assignment rows and six observed certificate
fingerprints, including material outside the planning window.

## Interpretation and limits

Worker timestamps are UTC wall-clock values returned as plain SQL TIMESTAMP.
Comparisons use the explicit UTC assessment, not the machine's local timezone.
`cert_is_expired` follows the current clock and includes not-yet-valid certificates;
this fixed-date analysis instead compares the two returned validity boundaries.
Expiry exactly on the requested horizon is included, provided the certificate is
currently time-valid at assessment.

The profile summary identifies six leaves, one Ed25519 key type and six SAN entries.
The work list preserves the selected SANs and key type as handoff context. This
neither recommends an algorithm nor verifies that a service matches the names.
Missing material remains unknown. Fingerprints identify certificate bytes; subject
names, serials and SAN text alone are not certificate identities.

Parsing does not validate a trust chain, check revocation, verify DNS names or
establish what a server presents. Subject/issuer equality establishes self-issued
names, not a valid signature. The generator establishes that these particular test
fixtures were self-signed. The notebook performs no live TLS inspection or service
modification. Malformed bytes raise parsing errors; SQL NULL remains NULL, and
both behaviors are checked separately. No production-compliance claim is made.

## Surface coverage

[coverage.json](coverage.json) records complete released and current public catalogs
and maps focused examples to visible executed SQL, results and interpretations.
The catalog has **14 logical named surfaces**, requiring seven for the fleet target.
Eight are covered by this offline narrative: fingerprint, subject, issuer, both
validity boundaries, SANs, CA flag and public-key algorithm. Serial values are
retained but are not counted merely because they are displayed. The current-clock
predicate, signature algorithm, long-form info, field-reference view and live TLS
inspection remain outside this story.

Examples execute release v0.4.0. Current-main baseline
`6f0e8893f5c461f112d2076450869c1bff776475` has the same names and signatures.
Ten stable scalar outputs agree for all six supplied fixtures across both actual
runtimes. Current source also refines unknown-algorithm naming; the Ed25519 fixtures
do not exercise that difference. Reviewed interface coverage is separate from exact
runtime coverage; the notebook does not claim to execute current-main code.

Repository checks use local loopback TLS fixtures for transport behavior. Structural
metadata validation skips example execution because metadata contains an external
TLS endpoint. No external metadata example is run during notebook validation.

Verification passed: 17 executed code cells, nine SQL cells, two SVG charts, twelve
SQL checks, two count reconciliations and the malformed-input probe. The default
took 18.0 seconds; the detached horizon-60 run took 5.6 seconds, beginning with no
fixture companions and retrieving all twelve verified files. All four figures were
reviewed, and parsed tables, byte-audit results and profile outputs match between
runs. Three runner protections and two parameter rejections preserve defaults.

A fresh Python 3.12 kernel completed the notebook after base-only installation
with pandas 2.2.3, Matplotlib 3.10.0, IPython 8.30.0, ipykernel 6.17.1 and
jupyter-client 7.4.9 already imported. Those versions remained unchanged and
`pip check` passed. This tests local compatibility, not a manually hosted Colab run.
Source checks passed 29 Go tests, 71/77/71 SQL assertions over stdio/HTTP/Unix,
build, vet, formatting, golangci-lint, and metadata (100/100, L1, zero findings).
Worker source, Go manifests and fixture bytes remain unchanged.

<p><a href="https://query.farm/"><img src="https://raw.githubusercontent.com/Query-farm/vgi-example-notebooks/v0.1.1/assets/query-farm-strata-sun.svg" alt="Query.Farm — Strata Sun" width="252"></a></p>
