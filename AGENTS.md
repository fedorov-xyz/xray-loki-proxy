# Agent notes — xray-core-loki-proxy

Small Go proxy: accepts raw Xray-core access log lines via `/vector/ingest`, parses them into `LogEntry`, applies skip rules, optionally notifies on torrent tags, then emits NDJSON to exactly one sink — `VECTOR_ENDPOINT` (HTTP) or `OUTPUT_FILE` (append).

## Layout

| File | Role |
|------|------|
| `main.go` | HTTP handlers (`/vector/ingest`, readiness), sink config validation, regex `xrayLogFormat`, file writer |
| `parse.go` | `LogEntry`, `parseLog` (route arrows → ` - `; timed PTR → `to_addr`) |
| `vector.go` | Vector ingest handler, parallel line processing, emit to file or HTTP |
| `skip.go` | domain/IP skip rules |
| `torrent.go` | batched torrent notify (`LogEntry` payload) |
| `log.go` / `utils.go` | logging + `getEnv` |
| `parse_test.go` / `vector_test.go` | parse JSON-contract + ingest/process tests |

## Commands

```bash
# tests (also run by pre-commit on Go changes)
go test ./...
go test -count=1 -v ./...

# format / static check
gofmt -w .
go vet ./...

# local binary
go build -o xray-loki-proxy .

# run (exactly one sink)
OUTPUT_FILE=/tmp/access.log.json LISTEN_PORT=8080 ./xray-loki-proxy
# or:
VECTOR_ENDPOINT=http://vector:8080 LISTEN_PORT=8080 ./xray-loki-proxy
```

Skip rules path is fixed: `/etc/xray-loki-proxy/skip-rules.json` (optional).

## Pre-commit

Config: `.pre-commit-config.yaml` — `gofmt`, `go vet`, `go test`.

```bash
pip install pre-commit   # or: brew install pre-commit
pre-commit install
pre-commit run --all-files
```

Hooks run automatically on `git commit` when staged changes include Go files.

## Conventions for agents

- Use [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary` (e.g. `test: cover parseLog optional fields`, `fix(parse): ...`, `chore: ...`). Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, etc.
- Keep parse fixtures randomized (IPs/domains/emails/inbound tags); do not paste real production log payloads.
- Prefer table-driven tests next to the code under test (`*_test.go`).
- Do not assert on `to_addr` / `ToAddr` unless DNS is mocked — it comes from live reverse lookup.
- Match existing style: small focused diffs, no drive-by refactors or unsolicited README edits.
- Only commit when the user asks.
