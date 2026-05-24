# k2-rules

Rule bundle compiler for the k2 tunnel. Fetches domain/IP data from open sources and compiles `.k2b` binary bundles.

## Commands

```bash
go build -o k2-rules-gen .     # compile the generator
go run . -o dist/               # build all bundles (fetches upstream data, ~1 min)
go run . -o dist/ -country=ru   # build only one country (skips overseas, faster)
go test ./...                   # run unit tests (httptest-based, no network)
```

## Architecture

Single Go package, 6 files:
- `sources.go` — data source definitions (countries, services, URLs)
- `main.go` — build pipeline: fetch → parse → compile → write `.k2b` + `manifest.json`
- `exec.go` — `os/exec` wrapper
- `preresolve.go` — build-time DNS pre-resolution (multi-resolver UNION + EDNS0 Client Subnet) for HTTPDNS anchor IPs. See doc-comment in the file for the cascade rationale.
- `main_test.go` — unit tests for `fetchDomainList` / `extractHost` (httptest, no network)
- `preresolve_test.go` — unit tests for pre-resolve (mock `dns.Server`, no network)

## k2b Binary Format (v2)

Magic `K2RB`, 32-byte header, 36-byte index per set. Data sections: reversed-suffix domain tables, IPv4/IPv6 range pairs, exclude-domain tables. Must match the reader in the k2 engine (`rule.go`).

## Data Sources

- **v2fly/domain-list-community** — shallow-cloned at build time, parsed recursively with `include:` resolution
- **Loyalsoldier/geoip** — per-country CIDR lists; also used for overseas IP complement
- **citizenlab/test-lists** — CSV format (URL in col 0), CC-BY-SA 4.0
- **bootmortis/iran-hosted-domains** — plaintext FQDN list (Iran)
- **runetfreedom** — RKN blocked IP + domain registry mirror (Russia)

## CI

GitHub Actions daily at UTC 00:30. Only publishes a release (`vYYYY.MM.DD`) if bundle SHA256s differ from the previous release.

## Gotchas

- Requires `git` and `tar` on PATH (v2fly clone uses `tar xzf`)
- Unit tests cover the fetch/parse path only; k2b binary format correctness is still verified by downstream k2 engine integration
- `go.mod` specifies Go 1.25
- Adding a new country: add entry to `countries` slice in `sources.go`, use `citizenlabBasic()` helper for minimal setup (auto-adds ccTLD + citizenlab + geoip)
- `fetchDomainList` strips `domain:`/`full:` prefixes (v2ray ecosystem format)
- Pre-resolve adds 60–90s to build time (parallelism 8, ~50 domains × 8 resolvers × 2 qtypes). Failures are non-fatal: partial results still ship. Daily SHA may drift because GeoDNS PoP assignments vary — that's expected and not a regression.
