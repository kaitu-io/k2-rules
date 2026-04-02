# k2-rules

Auto-compiled routing rule bundles for [k2](https://github.com/kaitu-io/k2) tunnel.

## Bundles

| Bundle | Contents | Use Case |
|--------|----------|----------|
| `overseas.k2b` | google, facebook, telegram, twitter, netflix, discord, spotify, tiktok, openai, github, cloudflare, fastly | 翻出去（China → overseas） |
| `cn-direct.k2b` | geoip-cn, cn-sites, bilibili | 中国直连 / 翻回来 |

## Usage

Download bundles to k2's cache directory:

```bash
# Download latest bundles
curl -L https://github.com/kaitu-io/k2-rules/releases/latest/download/overseas.k2b -o ~/.cache/k2/rules/overseas.k2b
curl -L https://github.com/kaitu-io/k2-rules/releases/latest/download/cn-direct.k2b -o ~/.cache/k2/rules/cn-direct.k2b
```

## Build Locally

```bash
go run . -o dist/
```

## Data Sources

See [ATTRIBUTION.md](ATTRIBUTION.md) for upstream sources and licenses.

## Schedule

GitHub Actions rebuilds daily at UTC 00:00. Each release is tagged `vYYYY.MM.DD`.
