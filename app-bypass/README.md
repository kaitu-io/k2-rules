# App Bypass YAML presets

Region-specific app-routing presets shipped via the same CDN as `.k2b` bundles. Each `app-bypass-<region>.yaml` file (where `<region>` is an ISO 3166-1 alpha-2 lowercase code) declares which installed apps the k2 engine should route direct on a user whose smart-routing region matches.

## Schema

Schema version 1. The validator (`tools/validate-app-bypass/main.go`) is the authoritative source — it rejects malformed files in CI before they reach the CDN.

```yaml
version: 1                       # required; reader rejects unknown versions
region: <iso-cc>                 # required; must equal filename's region code
description: |                   # optional; ignored by the parser
  Free-form maintainer notes.

# ── Android (case-sensitive reverse-domain identifiers) ──
android:
  installer_exact:
    - <packageName-of-installer>
  package_exact:
    - <packageName>
  package_prefix:
    - <packagePrefix>.           # MUST end with a dot

# ── Desktop (case-insensitive, one entry covers macOS/Windows/Linux) ──
desktop:
  process_exact:
    - <basename>
  process_prefix:
    - <basenamePrefix>
```

## Matching semantics

| YAML field | Matched against | Comparison |
|---|---|---|
| `android.installer_exact` | `PackageManager.getInstallSourceInfo(pkg).installingPackageName` | exact, case-sensitive |
| `android.package_exact` | `packageName` | exact, case-sensitive |
| `android.package_prefix` | `packageName` | `strings.HasPrefix`, case-sensitive |
| `desktop.process_exact` | `ProcessSearcher` returned process name | `strings.EqualFold` (case-insensitive) |
| `desktop.process_prefix` | same | `strings.HasPrefix(lower, lower)` |

Desktop entries are normalized to lowercase at compile-time inside the engine — write them in whatever case is natural; the engine lowercases at load.

## Hard rules (validator enforces these)

- `version: 1` required.
- `region:` must match filename (`app-bypass-cn.yaml` → `region: cn`).
- `package_prefix` entries MUST end with a dot. (`com.tencent.` not `com.tencent`.) The validator rejects the file otherwise. Reason: `com.tencent` would also match `com.tencentlabs.foo` etc.
- No empty strings, no whitespace-only entries.
- ≤ 500 entries per platform section.
- Duplicate entries within or across kinds (exact ∪ prefix) are rejected.

## Maintenance SOP

### Adding an entry

1. **Verify the package**: install the actual app on a fresh device, then `adb shell pm list packages -f` to grab the exact `packageName`. Don't rely on store listings — they sometimes show legacy names.
2. **Pick the right kind**:
   - `installer_exact`: the app store itself. One entry covers every app installed via that store.
   - `package_exact`: a specific app whose namespace is shared with foreign apps (don't prefix-match if collisions exist).
   - `package_prefix`: a vendor namespace dedicated to the target region (`com.tencent.` for Tencent's CN ecosystem).
3. **Open a PR** to this repo. CI runs the validator + builds a fresh bundle.
4. **Merge** → daily-build.yml ships the new YAML to the CDN within 24h. Devices pick it up on next rule refresh (engine refreshes hourly).

### Removing an entry

1. Open PR deleting the line.
2. Merge → CDN updated → devices pick up the smaller list on next refresh.
3. Rolling back stale installs: cannot — the YAML on a user's disk persists until the next refresh tick. Acceptable since "this app no longer needs bypass" is rarely time-critical.

### Emergency rollback (bad pattern blocks an app)

If a recently-shipped YAML breaks user experience:

1. Identify the bad entry (usually via user feedback — "X app started crashing/timing out").
2. PR to remove or correct the entry.
3. Merge ASAP — CDN serves the new file within minutes once the GitHub release publishes.
4. Tell user to disconnect + reconnect to pick up the new bundle (or wait ≤1 hour for the engine's auto-refresh).

For a full preset rollback (entire region preset is broken):
- Revert the `app-bypass-<region>.yaml` commit.
- Devices fall back to the previous bundle content already on disk.
- They re-fetch on next refresh and get the rolled-back version.

### Testing locally before PR

```bash
# 1. Validate schema
go run ./tools/validate-app-bypass app-bypass/

# 2. Build a fresh bundle and verify the YAML is included
go build -o /tmp/k2-rules-gen .
/tmp/k2-rules-gen -o /tmp/dist/
ls /tmp/dist/app-bypass-*.yaml          # your new file should be here

# 3. Test against a real k2 install (advanced)
#    Copy /tmp/dist/app-bypass-<region>.yaml into the k2 rule cache:
#      macOS:   ~/Library/Caches/kaitu/rules/
#      Linux:   ~/.cache/kaitu/rules/
#      Windows: %LOCALAPPDATA%\kaitu\rules\
#    Restart the k2 daemon and verify app-bypass-preview action
#    returns the expected matches:
#      curl -X POST http://127.0.0.1:1777/api/core \
#        -d '{"action":"app-bypass-preview"}'
```

### File anatomy

| File | What it does |
|---|---|
| `cn.yaml` | China region — top-of-funnel ecosystem |
| `ir.yaml` | Iran region — banking + taxi + gov + main stores |
| (future) | `ru.yaml`, `tr.yaml`, etc. as user demand surfaces |

## Privacy

Each YAML file is **public**. Anyone with the CDN URL can read which apps the publisher considers regionally-locked. This is the same threat model as the `.k2b` rule files. Do not include user data here; only publisher-curated patterns.

## See also

- Spec: [`docs/superpowers/specs/2026-05-25-app-bypass-engine-managed-design.md`](https://github.com/kaitu-io/k2app/blob/main/docs/superpowers/specs/2026-05-25-app-bypass-engine-managed-design.md)
- Validator: [`tools/validate-app-bypass/main.go`](../tools/validate-app-bypass/main.go)
- k2 engine consumer: [`k2/appbypass/`](https://github.com/kaitu-io/k2/tree/master/appbypass)
