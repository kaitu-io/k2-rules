# Attribution

This project compiles routing rule data from the following open sources. All
data is published unmodified under the terms of the respective licenses;
downstream consumers of the generated `.k2b` bundles are responsible for
preserving attribution as required.

## Domain Data

- **v2fly/domain-list-community** — MIT License
  - https://github.com/v2fly/domain-list-community
  - Copyright (c) 2017–present v2fly contributors
  - Used for: `overseas`, `cn-sites`, `ir-sites`, `ru-sites`, `mm-sites`

- **citizenlab/test-lists** — CC-BY-SA 4.0
  - https://github.com/citizenlab/test-lists
  - Copyright (c) The Citizen Lab, University of Toronto
  - Used for: the domain side of `ir/ru/tr/pk/vn/mm/eg/id/sa/ae/th/bd/by`
    direct-bundles, and for `ir-blocked` / `ru-blocked` reserved sets.
  - **Attribution requirement**: derivative distributions (the `.k2b` bundles)
    must carry this attribution file. Consumers that redistribute rule bundles
    must either (a) ship this file alongside the bundle or (b) link to this
    repository's README.

- **bootmortis/iran-hosted-domains** — MIT License
  - https://github.com/bootmortis/iran-hosted-domains
  - Used for: Iranian-hosted domains in `ir-sites` (~130k curated entries,
    pulled from the project's `releases/latest/download/domains.txt` asset).

## IP Data

- **Loyalsoldier/geoip** — CC-BY-SA 4.0
  - https://github.com/Loyalsoldier/geoip
  - Copyright (c) Loyalsoldier
  - Used for: `geoip-cn`, `geoip-ir`, `geoip-ru`, `geoip-tr`, `geoip-pk`,
    `geoip-vn`, `geoip-mm`, `geoip-eg`, `geoip-id`, `geoip-sa`, `geoip-ae`,
    `geoip-th`, `geoip-bd`, `geoip-by`, and the "all non-CN IPs" complement
    used in the `overseas` bundle.
  - IP-CIDR data used unmodified under CC-BY-SA 4.0 terms.

- **runetfreedom/russia-blocked-geoip** — MIT License
  - https://github.com/runetfreedom/russia-blocked-geoip
  - Mirrors the Russian Federal Service for Supervision of Communications
    (Roskomnadzor / RKN) unified registry of blocked IPs. Auto-updated every
    6 hours from the official source.
  - Used for: the IP side of `ru-blocked` (reserved for a future
    force-proxy privacy mode).

## Official Public IP Ranges

- **Telegram** — https://core.telegram.org/resources/cidr.txt
- **Google** — https://www.gstatic.com/ipranges/goog.json
- **Cloudflare** — https://www.cloudflare.com/ips-v4 / https://www.cloudflare.com/ips-v6

These are published publicly by the respective services with no license
restrictions.

## License of Generated Bundles

The generated `.k2b` bundles contain data from sources with different licenses.
Where CC-BY-SA 4.0 applies (Citizen Lab, Loyalsoldier), the bundles inherit
the most restrictive applicable license: **CC-BY-SA 4.0**. This means
redistributors must:

1. Preserve attribution to the original sources (this file satisfies that
   requirement if distributed alongside the bundle).
2. License any derivative rule data under CC-BY-SA 4.0 or a compatible license.

The compiler tool (`k2-rules-gen`) source code itself remains under the
repository's project license and is not affected by the bundle license.
