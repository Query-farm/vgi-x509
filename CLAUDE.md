# CLAUDE.md — vgi-x509

Guidance for working in this repo. It is a **VGI worker** (Go) that parses X.509
certificates and inspects TLS endpoints as DuckDB SQL functions. Defensive
security / compliance tool. Catalog name: `x509`.

## Layout

```
cmd/vgi-x509-worker/   main(): catalog/schema tags, Register(), RunStdio/RunHttp/RunUnix
cmd/mockserver/        standalone TLS server presenting a self-signed cert (E2E only)
internal/x509worker/   the worker: cert.go (parsing), tls.go (inspection),
                       info.go (long-format dump), functions.go (VGI glue + Register),
                       meta.go (fixtures, examples, agent tasks, cert_fields view)
internal/testca/       self-signed cert generator (tests + mock server; NOT a real CA)
test/sql/*.test        haybarn-unittest SQL E2E (cert_offline, tls_inspect, tls_pin)
ci/run-integration.sh  the SQL E2E driver used by CI and `make test-sql`
vgi-agent-tests.yaml   private graders for the agent tasks (keyed by task name)
vgi-lint.toml          vgi-lint settings (fail_on = info, location)
```

The worker exposes 11 scalars, 2 table functions (`cert_info`, `tls_inspect`)
and 1 view (`cert_fields`).

## Go VGI pattern

- `vgi.NewWorker(...)` → `w.RegisterScalar(...)` / `w.RegisterTable(...)` → `w.RunStdio()`.
- **Scalars** implement `vgi.ScalarFunction` directly (`Name`, `Metadata`,
  `ArgumentSpecs`, `OnBind`, `Process`). We have one struct per return-type
  family (`certStringScalar`, `certBoolScalar`, `certTimestampScalar`,
  `certSANsScalar`), each parameterised by name/description/accessor so the SDK
  boilerplate isn't repeated per function. String/bool scalars use
  `vgi.MapColumn` (auto NULL propagation); timestamp and list scalars build the
  Arrow array by hand (the builder constructors take extra args, so the generic
  `MapColumn` doesn't fit) and wrap with `vgi.BuildResultBatch`.
- **Table functions** (`cert_info`, `tls_inspect`) implement
  `vgi.TypedTableFunc[S]` and register via `vgi.AsTableFunction[S](...)`. Args
  via a tag struct + `vgi.DeriveArgSpecs` / `vgi.BindArgs`. Build columns →
  `array.NewRecordBatch` → `out.Emit` / `out.Finish`.

## gob-state gotcha (CRITICAL)

Table-function state is **gob-encoded** by the SDK between `NewState` and
`Process` (it may cross a process boundary). State structs must hold only
**exported, gob-encodable** fields — no `arrow.Record`, interfaces, channels,
funcs, or unexported fields. The SDK now **panics at registration** otherwise.

So each table function does all parsing / network work eagerly in `NewState` and
stores plain exported Go slices plus an `Offset` cursor, then rebuilds the Arrow
batch in `Process`. The cursor must live in the state (not a `Done bool` flipped
after `Emit`): over HTTP the state round-trips through a continuation token and a
post-Emit flag is lost, so the scan never ends. See `certInfoState` (parallel
`Fields`/`Values` slices) and `tlsInspectState` (`[]tlsChainRow` with timestamps
stored as `int64` micros, not `time.Time` — keep it boring and encodable).
`TestRegisterDoesNotPanic` and `TestCursorSurvivesContinuation` guard this.

## PEM-vs-DER dispatch

A certificate arrives as **either** PEM text (`VARCHAR`) or DER bytes (`BLOB`).
The cert argument is declared with Arrow type `any` (scalars: `ArrowType: "any"`;
`cert_info`: `[]byte` field with `vgi:"...,type=any,..."`). At runtime
`certBytesAt` pulls bytes from whichever column type arrived
(`*array.String`/`*array.LargeString`/`*array.Binary`/`*array.LargeBinary`), then
`ParseCertificate` sniffs the **content**: leading `-----BEGIN` → PEM decode,
else → DER. One code path, both SQL input types.

Malformed input → a clear error (whole batch fails, mirroring DuckDB scalar
semantics). NULL cert → NULL output (scalars) / zero rows (`cert_info`).

## Timestamps

`tsType` is `&arrow.TimestampType{Unit: arrow.Microsecond}` with **no TimeZone**,
so DuckDB sees a plain `TIMESTAMP` (not `TIMESTAMPTZ`). Values are UTC
wall-clock micros (`time.UnixMicro`). Setting a TimeZone makes DuckDB render
`...+00`, which breaks the `.test` expectations.

## tls_inspect

Defensive inspection: `insecure := true` by default
(`InsecureSkipVerify`) so we inspect whatever a server presents (expired /
self-signed included). Dial + handshake are bounded by `timeout_ms` via a
context deadline — it never hangs. **AUTHORIZED endpoints only** (it opens a
network connection). Document this everywhere it appears.

## Tests / haybarn

- Unit tests generate self-signed certs in-process via `internal/testca` and
  assert every scalar over PEM **and** DER inputs, malformed → error, NULL →
  NULL, plus `tls_inspect` against an in-process TLS server.
- SQL E2E (`haybarn-unittest` **2.0**; 1.x cannot attach a vgi.v3 worker and
  rejects `--keep-home`): `require vgi` is **silently SKIPPED**, so use
  `statement ok` + `LOAD vgi;` and `ATTACH 'x509' ... (TYPE vgi, LOCATION
  '{VGI_X509_WORKER}')`. Env vars use the `{VAR}` form (2.0 deprecates
  `${VAR}`). Each file starts with `# group: [vgi_x509]`.
  `cert_offline.test` drives the pure functions over the **committed PEM
  literals** (`fixturePEM` and `legacyPEM` in meta.go; regenerate with a
  throwaway program if one must change, then update the asserted fingerprints
  and serials). `tls_inspect.test` uses `require-env VGI_X509_TEST_ADDR` and
  `insecure := true`; `tls_pin.test` also needs `VGI_X509_TEST_CERT_FILE` (the
  mock's certificate, written by `mockserver --cert-out`) to prove a positive
  fingerprint match.
- **Table functions can't take subqueries** in DuckDB — pass `cert_info` a PEM
  string literal, not `(SELECT ... )`.
- `make test-sql` builds the worker and runs `ci/run-integration.sh` (the CI
  driver): it starts `mockserver` (which prints `PORT:<n>` and `CN:<cn>`),
  exports `VGI_X509_TEST_ADDR` and `VGI_X509_TEST_CERT_FILE`, runs haybarn with
  `--keep-home`, fails if every test was skipped, and kills the mock on exit.
  `TRANSPORT=http|unix` switches the worker transport.

## Examples and agent tasks

- Example SQL is defined once in Go and referenced. Composed examples (several
  objects in one query) are `Composed*Example` in meta.go; each is in the
  schema-level `vgi.example_queries` (offline ones) and in the first five
  examples of the function that drives it, because the vgi-lint agent simulator
  only shows per-object examples. `TestComposedExamplesOnDrivingObjects` and
  `TestExampleListsWithinAgentLimit` (8,000 chars per example list, VGI417) guard
  this.
- Agent task prompts (`AgentTestTasksJSON`) are public; their graders live in
  `vgi-agent-tests.yaml`. `TestAgentTasksMatchSidecar` keeps the names in sync.
  Exact-compare prompts must pin the answer shape (rows, columns, types). The
  live task is graded by `check_sql` against a temp table the analyst creates,
  so a wrong answer fails.

## Verify

```sh
export PATH="$HOME/.local/bin:$PATH"   # haybarn-unittest 2.0
go build ./... && go vet ./... && gofmt -l . && go test ./... && golangci-lint run
make test-sql                          # also TRANSPORT=http, TRANSPORT=unix
make build && uvx --prerelease allow --from 'vgi-lint-check>=2.5.1' vgi-lint lint \
    --execute --execute-mode run --fail-on info
```
