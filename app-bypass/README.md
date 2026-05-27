# App Bypass YAML presets

Region-specific app-routing presets, schema v2. **Compile sources only** — these YAMLs are read by the `k2-rules-gen` build pipeline and compiled into the AndroidInstallers / AndroidApps / WindowsApps / DarwinApps sections of `dist/<region>.krs`. The YAML files themselves are **not** published to CDN; only the compiled `.krs` binary ships.

Authoritative validator: `tools/validate-app-bypass/main.go` — run in CI before any release.

## Schema (v2)

```yaml
version: 2                         # required; validator rejects anything else
region: <iso-cc>                   # required; must equal filename's region code
description: |                     # optional; ignored at compile time
  Free-form maintainer notes.

# ── Android (case-sensitive package names) ──
android:
  installers:                      # exact-match strings (NO glob — '*' is rejected)
    - com.xiaomi.market
    - com.huawei.appmarket
  apps:                            # glob patterns (single-* semantics, case-sensitive)
    - "com.tencent.*"              # matches com.tencent.mm, com.tencent.qq, etc.
    - "com.eg.android.AlipayGphone" # literal pattern (no '*') is exact match

# ── Windows (case-insensitive; compiler lowercases) ──
windows:
  apps:                            # glob, lowercased at compile
    - "WeChat*"                    # matches WeChat.exe, WeChatHelper.exe, etc.

# ── macOS (case-sensitive process basenames) ──
darwin:
  apps:                            # glob, case preserved
    - "WeChat"                     # exact match for "WeChat" only
    - "WeChatHelper*"              # prefix glob
```

## Glob semantics

Single `*` matches **zero or more arbitrary characters**. No `?`, `[...]`, brace expansion, or path-segment semantics.

| Pattern | Matches | Doesn't match |
|---------|---------|---------------|
| `WeChat` | `WeChat` only | `WeChatHelper` |
| `WeChat*` | `WeChat`, `WeChatHelper`, `WeChat.exe` | anything not starting with `WeChat` |
| `*chat` | `chat`, `wechat` | `chats`, `chatter` |
| `*chat*` | `WeChat`, `chat`, `chatter` | anything not containing `chat` |
| `Wei*Chat` | `WeiChat`, `WeiXinChat` | `WeChat` |

Case handling:
- **windows.apps** — patterns lowercased at compile; reader lowercases queries before matching.
- **android.apps / darwin.apps** — case preserved both ends.

## Validator rules

The validator (`tools/validate-app-bypass`) rejects:

- `version` ≠ 2
- `region:` value mismatching the filename
- Unknown top-level fields (strict YAML parsing)
- Empty entries or leading/trailing whitespace
- Entry length > 256 bytes
- > 500 entries per platform section
- Duplicates within a section
- `*` inside an `installers` entry (installers are exact-match)
- The all-wildcard pattern `"*"` (almost certainly an accidental wildcard)
- Whitespace inside entries

Run locally before opening a PR:

```bash
go run ./tools/validate-app-bypass app-bypass/
```

## Maintenance SOP

### Adding an entry

1. **Verify the package/process name**: install the real app and inspect:
   - Android: `adb shell pm list packages -f`
   - macOS: `lsof -p $(pgrep -f 'AppName' | head -1)` or `ps -A -o comm | grep -i app`
   - Windows: Task Manager → Details tab, exact `.exe` name
2. **Pick the right section**:
   - `android.installers` — the app store itself (one entry → every app installed via that store)
   - `android.apps` — a specific app or vendor namespace (`com.tencent.*`)
   - `windows.apps` / `darwin.apps` — desktop process basenames
3. **Test locally**:

```bash
# Validate schema
go run ./tools/validate-app-bypass app-bypass/

# Run the full krs/ test suite (round-trip + match correctness)
go test ./krs/

# Build a .krs locally and inspect the manifest
go run . -o /tmp/dist -country=cn
ls /tmp/dist/cn.krs
cat /tmp/dist/manifest.json | jq .bundles.cn
```

4. **Open a PR**. CI runs the validator + krs/ tests.
5. **Merge** → daily-build.yml ships the new `.krs` to CDN within 24h. Devices pick it up on next rule refresh.

### Removing an entry

1. Open PR deleting the line.
2. Merge → CDN updated → devices pick up the smaller list on next refresh.

### Emergency rollback (bad pattern blocks an app)

1. Identify the bad entry from user reports.
2. PR to remove or correct.
3. Merge → CI publishes the new bundle within minutes.
4. Tell affected user to reconnect (or wait ≤1 hour for engine auto-refresh).

For full preset rollback (entire region broken):
- Revert the offending commit on `master`.
- Devices fall back to the previous bundle on disk until the next refresh.

## File anatomy

| File | What it does |
|---|---|
| `cn.yaml` | China region — top-of-funnel ecosystem (Tencent, Alibaba, ByteDance, etc.) |
| `ir.yaml` | Iran region — banking + Cafe Bazaar / Myket app stores + taxi |
| (future) | `ru.yaml`, `tr.yaml`, etc. as user demand surfaces |

## Privacy

Each YAML file is **public source** (in this repo). The compiled `.krs` is **also public** (CDN-served). Anyone with the URL can read which apps the publisher considers regionally-locked. This is the same threat model as the legacy `.k2b` rule files. Do not include user data here — only publisher-curated patterns.

## See also

- `.krs` wire format & TypeID namespace — repo root `CLAUDE.md`
- Reader / writer / match library — `github.com/kaitu-io/k2-rules/krs`
- Validator — `tools/validate-app-bypass/main.go`
