# Agent notes — xray-core-loki-proxy

Small Go proxy: accepts Loki `logproto` push requests, parses Xray-core access log lines into `LogEntry`, applies skip rules, optionally notifies on torrent tags, appends JSON lines to `OUTPUT_FILE`. Also exposes `/vector/ingest` which emits `LogEntryV2` NDJSON for Vector.

## Layout

| File | Role |
|------|------|
| `main.go` | HTTP handlers (`/loki/api/v1/push`, `/vector/ingest`, readiness), regex `xrayLogFormat`, file writer |
| `parse.go` | `LogEntry` / `LogEntryV2`, `parseLog` / `parseLogV2` (route arrows → ` - `; optional PTR → `to_addr`) |
| `vector.go` | Vector ingest handler + line processing |
| `skip.go` | destination parsing, domain/IP skip rules |
| `torrent.go` | batched torrent notify |
| `log.go` / `utils.go` | logging + `getEnv` |
| `parse_legacy_test.go` / `parse_v2_test.go` | detailed behavior + JSON-contract tests for legacy and v2 |

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

# run (needs OUTPUT_FILE)
OUTPUT_FILE=/tmp/access.log.json LISTEN_PORT=8080 ./xray-loki-proxy
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
