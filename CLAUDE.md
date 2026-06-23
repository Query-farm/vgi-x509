# CLAUDE.md — vgi-x509

Guidance for working in this repo. It is a **VGI worker** (Go) that parses X.509
certificates and inspects TLS endpoints as DuckDB SQL functions. Defensive
security / compliance tool. Catalog name: `x509`.

## Layout

```
cmd/vgi-x509-worker/   main(): build the worker, Register(), RunStdio()
cmd/mockserver/        standalone TLS server presenting a self-signed cert (E2E only)
internal/x509worker/   the worker: cert.go (parsing), tls.go (inspection),
                       info.go (long-format dump), functions.go (VGI glue + Register)
internal/testca/       self-signed cert generator (tests + mock server; NOT a real CA)
test/sql/*.test        haybarn-unittest SQL E2E
```

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
stores plain exported Go slices plus a `Done bool`, then rebuilds the Arrow batch
in `Process`. See `certInfoState` (parallel `Fields`/`Values` slices) and
`tlsInspectState` (`[]tlsChainRow` with timestamps stored as `int64` micros, not
`time.Time` — keep it boring and encodable). `TestRegisterDoesNotPanic` guards
this.

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
- SQL E2E (`haybarn-unittest`): `require vgi` is **silently SKIPPED**, so use
  `statement ok` + `LOAD vgi;` and `ATTACH 'x509' ... (TYPE vgi, LOCATION
  '${VGI_X509_WORKER}')`. Each file starts with `# group: [vgi_x509]`.
  `cert_offline.test` drives the pure functions over a **committed PEM literal**
  (regenerate it with a throwaway `cmd/genpem` if the fixture must change — then
  update the embedded fingerprint). `tls_inspect.test` uses
  `require-env VGI_X509_TEST_ADDR` and `insecure := true`.
- **Table functions can't take subqueries** in DuckDB — pass `cert_info` a PEM
  string literal, not `(SELECT ... )`.
- The `Makefile` `test-sql` target builds both binaries, starts `mockserver`
  (which prints `PORT:<n>` and `CN:<cn>`), exports `VGI_X509_WORKER` +
  `VGI_X509_TEST_ADDR=127.0.0.1:<port>`, runs haybarn, then `trap`-kills the
  mock server and propagates haybarn's exit status.

## Verify

```sh
export PATH="$HOME/.local/bin:$PATH"
go build ./... && go vet ./... && gofmt -l . && go test ./...
make test-sql
```
