# k2-rules

Rule bundle compiler for the k2 tunnel. Fetches domain/IP data from open sources and compiles `.k2b` binary bundles.

## Commands

```bash
go build -o k2-rules-gen .     # compile the generator
go run . -o dist/               # build all bundles (fetches upstream data, ~1 min)
go run . -o dist/ -country=ru   # build only one country (skips overseas, faster)
```

## Architecture

Single Go package, 3 files:
- `sources.go` — data source definitions (countries, services, URLs)
- `main.go` — build pipeline: fetch → parse → compile → write `.k2b` + `manifest.json`
- `exec.go` — `os/exec` wrapper

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
- No tests — correctness verified by downstream k2 engine integration
- `go.mod` specifies Go 1.25
- Adding a new country: add entry to `countries` slice in `sources.go`, use `citizenlabBasic()` helper for minimal setup (auto-adds ccTLD + citizenlab + geoip)
- `fetchDomainList` strips `domain:`/`full:` prefixes (v2ray ecosystem format)
