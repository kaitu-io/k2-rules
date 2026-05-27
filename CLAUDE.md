# k2-rules

Rule bundle compiler **and** Go library for the k2 tunnel. Two responsibilities:

1. **Compiler** (`main.go`): fetches domain/IP data from open sources, compiles `.k2b` (legacy) and `.krs` (current) binary bundles, publishes alongside `manifest.json`.
2. **Library** (`krs/` sub-package): writer + reader + match APIs. k2 imports `github.com/kaitu-io/k2-rules/krs` and gets everything it needs to consume `.krs` bundles — no parallel format implementation in the k2 repo.

This repo **owns the .krs format**. k2 is a consumer. Format / writer / reader are co-located here so they cannot drift.

## Commands

```bash
go build -o k2-rules-gen .     # compile the generator
go run . -o dist/               # build all bundles (fetches upstream data, ~1 min)
go run . -o dist/ -country=ru   # build only one country (skips overseas, faster)
go test ./...                   # run unit tests (httptest-based, no network)
```

## Architecture

```
k2-rules/
├── main.go, sources.go, exec.go, preresolve.go     — compiler CLI (package main)
├── krs/                                             — public library (package krs)
│   ├── format.go      — magic, TypeID enum, layout constants
│   ├── writer.go      — WriteBundle
│   ├── reader.go      — ReadBundle, Load
│   ├── domain.go      — NamedSet.MatchDomain (reversed-suffix binary search)
│   ├── ip.go          — NamedSet.MatchIP (range binary search)
│   ├── glob.go        — single-* glob matcher for app patterns
│   └── match.go       — AppPatterns, MatchInstalled, Index
├── app-bypass/                                      — YAML compile sources
│   ├── cn.yaml, ir.yaml      — v2 schema (android/windows/darwin)
│   └── README.md
└── tools/validate-app-bypass/                       — v2-schema validator
```

YAML files in `app-bypass/` are **compile sources only** — they are read by `main.go`, compiled into `.krs`, and **not published to dist/**. Maintainers edit YAML, CI compiles, CDN serves `.krs`.

## .krs Binary Format

Magic `K2RL`. Single file format, **no version number in the filename** — forward-compat is achieved via TypeID enum extension (unknown TypeIDs are silently skipped by readers).

### Layout

All multi-byte integers are little-endian.

```
OFFSET  SIZE  CONTENT
0       4     Magic "K2RL"
4       2     Format version uint16 (=1, informational; does NOT gate parsing)
6       2     Section count uint16
8       N     Section index: count × 10 bytes
                +0  uint16  TypeID
                +2  uint32  Offset (absolute, from file start)
                +6  uint32  Length (payload bytes)
...     M     Section payloads, concatenated in any order
              (index is authoritative — file order does not matter)
```

**Version field semantics**: writer stamps the highest TypeID generation it knows. Reader logs warning on version mismatch but **does not reject**. Forward-compat lives entirely in the TypeID enum: append-only, unknown IDs skipped.

### TypeID namespace

```
Metadata          0x0000-0x000F:
  0x0001  SetTable               u16 count + [uvarint(len) + utf-8 name] × count
                                 Position in table is the set_idx referenced
                                 by per-set sections below.

Per-set routing   0x0010-0x001F:  entries prefixed with u16 set_idx
                                  sorted by (set_idx ASC, value ASC)
  0x0010  IPv4RangesBySet         entry: u16 set_idx + 4B start + 4B end
                                  IP addresses are raw bytes in network byte
                                  order (big-endian). Sort key for ranges:
                                  set_idx ASC, then byte-wise on start.
  0x0011  IPv6RangesBySet         entry: u16 set_idx + 16B start + 16B end
                                  Same encoding as IPv4 — raw network-order bytes.
  0x0012  DomainSuffixBySet       entry: u16 set_idx + uvarint(len) + reversed-lower utf-8
  0x0013  DomainExcludeBySet      entry: u16 set_idx + uvarint(len) + reversed-lower utf-8

Flat app patterns 0x0100-0x05FF:  entry: uvarint(len) + utf-8, sorted ASC
  0x0100  AndroidInstallers       exact match, case-sensitive
  0x0101  AndroidApps             glob, case-sensitive
  0x0200  WindowsApps             glob, lowercased at compile (case-insensitive match)
  0x0300  DarwinApps              glob, case-sensitive
  0x0400  IOSApps                 (reserved)
  0x0500  LinuxApps               (reserved)
```

**Reserved namespaces**: 0x0014-0x001F (future routing), 0x0102-0x01FF, 0x0201-0x02FF, 0x0301-0x03FF (future platform sub-categories), 0x0600+ (future platforms).

### Glob semantics (app patterns)

Single wildcard `*` matches zero or more characters. No `?`, `[...]`, brace expansion, or path-segment semantics. Empty pattern `""` is invalid (rejected at compile).

### File naming

CDN artifacts: `<region>.krs` (e.g. `cn.krs`, `ir.krs`). One file per region, all rule types unified. Aggregated bundles use any name (e.g. `overseas.krs`).

The legacy `.k2b` format continues to ship for ~6 months alongside `.krs` (separate writers, no format coupling). Both feed the same manifest.

## k2 Migration Contract

k2 imports `github.com/kaitu-io/k2-rules/krs`. API mapping from the old k2-side packages:

| Old (k2 repo) | New (k2-rules/krs) |
|---|---|
| `rule.Load(dir)`, `rule.ReadBundle(data)` | `krs.Load(dir)`, `krs.ReadBundle(data)` |
| `rule.Bundle`, `rule.BundleSet` | `krs.Bundle`, `krs.NamedSet` |
| `BundleSet.MatchDomain/MatchIP` | `NamedSet.MatchDomain/MatchIP` (same signatures) |
| `rule.Index(bundles)` | `krs.Index(bundles)` |
| `appbypass.Load`, `*Preset`, `MatchInstalled` | `bundle.Apps` field (\*AppPatterns), `krs.MatchInstalled` |
| `appbypass.AndroidPatterns.Package{Exact,Prefix}` | `AppPatterns.Android.Apps` (glob) — semantics change, see below |
| `appbypass.DesktopPatterns.Process{Exact,Prefix}` | `AppPatterns.Windows.Apps` + `AppPatterns.Darwin.Apps` (glob, platform-split) |

**Semantic change**: app matching becomes **single-`*` glob** (not prefix/exact). YAML migration handles this: `process_prefix: "WeChat"` → `windows.apps: ["wechat*"]` + `darwin.apps: ["WeChat*"]`.

## k2b Binary Format (legacy, v2)

Magic `K2RB`, 32-byte header, 36-byte index per set. Data sections: reversed-suffix domain tables, IPv4/IPv6 range pairs, exclude-domain tables. Must match the reader in the k2 engine (`rule.go`). Frozen — no new features here; new work goes into `.krs`.

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
- Unit tests cover the fetch/parse path + krs writer/reader round-trip; downstream k2 integration validates real-world matching
- `go.mod` specifies Go 1.25
- Adding a new country: add entry to `countries` slice in `sources.go`, use `citizenlabBasic()` helper for minimal setup (auto-adds ccTLD + citizenlab + geoip)
- `fetchDomainList` strips `domain:`/`full:` prefixes (v2ray ecosystem format)
- Pre-resolve adds 60–90s to build time (parallelism 8, ~50 domains × 8 resolvers × 2 qtypes). Failures are non-fatal: partial results still ship. Daily SHA may drift because GeoDNS PoP assignments vary — that's expected and not a regression.
- **Bundles are unsigned**. Both `.k2b` and `.krs` ship without detached signatures; integrity relies on CDN trust + manifest sha256. Adding signing is a future cross-repo coordination task (key generation, pubkey embed in k2 reader, CI secret).
- **Format ownership**: this repo defines `.krs`. k2 may not unilaterally introduce new TypeIDs or layout changes — coordinate via PR here first. New TypeIDs are append-only; bumping `Version` is informational; changing existing TypeID semantics is forbidden.
