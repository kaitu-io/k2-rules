package main

// service defines an upstream data source for a rule set.
type service struct {
	Name string

	// Domain sources: v2fly/domain-list-community data/{name} files.
	// include: directives are resolved recursively.
	V2flyNames []string

	// ExcludeAttr filters entries with this @ attribute into the exclude list.
	// For overseas: @cn entries (China-accessible endpoints like google.cn)
	//   become ExcludeDomainSuffixes — blocked by GFW except these.
	// For cn-direct: @!cn entries (overseas variants like hk.weibo.com)
	//   become ExcludeDomainSuffixes — Chinese except these subdomains.
	ExcludeAttr string

	// IP sources: URLs returning one CIDR per line (plain text).
	IPURLs []string

	// ComplementIPURL, if set, fetches CIDRs and computes their complement
	// (all public IPs NOT in the fetched ranges). Used to generate "all
	// non-Chinese IPs" from geoip-cn — eliminates IP middle ground.
	ComplementIPURL string

	// CitizenLabCSVURL points at a citizenlab/test-lists CSV (one URL per row,
	// col 0 = URL, header row skipped). Entries are URL-parsed and the host
	// component is emitted as a suffix match. Used as the universal base
	// domain layer for countries with no v2fly coverage.
	//
	// License: CC-BY-SA 4.0 — attribution required in ATTRIBUTIONS.md.
	CitizenLabCSVURL string

	// DomainListURLs are plaintext domain lists (one FQDN per line, # comments
	// allowed). Used for country-specific curated lists like bootmortis/iran-hosted-domains.
	DomainListURLs []string

	// OrphanDomains are hardcoded domain suffixes to add to this set.
	// Use sparingly — for critical domestic services that upstream data misses.
	OrphanDomains []string

	// PreResolveV2flyCategory names a v2fly data file whose domain entries are
	// resolved at build time and the resulting IPs added to this service's
	// CIDR set as /32 (IPv4) / /128 (IPv6). Used for HTTPDNS server anchors
	// whose IPs cannot be reliably pinned at runtime (e.g., apps that connect
	// to HTTPDNS by hardcoded IP without going through sys DNS).
	//
	// Resolution uses multi-resolver UNION with EDNS0 Client Subnet from
	// multiple geographic perspectives — see preresolve.go.
	PreResolveV2flyCategory string
}

// country groups the services that compose a single {cc}-direct.k2b bundle.
// The bundle contains one set per service. By convention, the set names follow
// "{cc}-sites" / "geoip-{cc}" / "{cc}-blocked" patterns so client-side presets
// can reference them unambiguously.
type country struct {
	Code     string // ISO 3166-1 alpha-2 lowercased, e.g. "cn", "ir", "ru"
	Name     string // Human-readable name for logging
	Services []service
}

// overseasServices defines the "overseas" rule set (sites blocked in China).
// Uses v2fly/geolocation-!cn (972 files recursive) + orphan blocked sites.
// Emits a single-set bundle overseas.k2b.
var overseasServices = []service{
	{
		Name: "overseas",
		V2flyNames: []string{
			"geolocation-!cn",
			// Orphan files: blocked in China but not in geolocation-!cn.
			"2ch", "annas-archive", "flibusta", "hdrezka", "kinopub", "meduza",
		},
		ExcludeAttr: "cn", // exclude China-accessible endpoints (google.cn, gstatic.cn)
		// Complement of geoip-cn: all non-Chinese, non-private IPs.
		// This ensures every public IP is classified as either cn or overseas.
		ComplementIPURL: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt",
	},
}

// countries defines the per-country direct-bundle pipeline. Each entry produces
// {code}-direct.k2b with one set per service.
//
// The default recipe per country is:
//   - "geoip-{cc}"  — Loyalsoldier geoip CIDRs (universal base IP layer)
//   - "{cc}-sites"  — v2fly (if available) + citizenlab CSV + curated lists
//
// RU and IR additionally get a "{cc}-blocked" set reserved for a future
// privacy/force-proxy mode. The set is populated now so bundle delivery is
// zero-latency when the consumer feature ships.
var countries = []country{
	// China — unchanged from original cn-direct.k2b schema.
	{
		Code: "cn", Name: "China",
		Services: []service{
			{
				// "geoip-cn" — the canonical IP layer of the CN bundle. Despite the
				// name, this set actually carries TWO logically distinct groups of
				// IPs, merged into a single set so they ship together to every
				// existing k2 client without requiring a binary release to update
				// the cn-access preset map:
				//
				//   1. Loyalsoldier cn.txt — mainland China geographic allocation.
				//      The traditional "geoip-cn" data; what users expect from the
				//      name. ~5,600 CIDRs, daily refresh from upstream.
				//
				//   2. HTTPDNS server anchor IPs — build-time multi-resolver UNION
				//      of v2fly category-httpdns-cn. These are the PoP IPs (often
				//      Tencent HK / overseas, e.g. 43.129.138.0/24) at which
				//      mainland HTTPDNS services answer. Pinning them as direct
				//      breaks the cascade that causes apps like WeChat — which
				//      sometimes connect to HTTPDNS via hardcoded IPs and bypass
				//      sys DNS — to route AU→CN→HK for what should be a local
				//      connection. With these IPs direct, the HTTPDNS server sees
				//      the real CN source and returns mainland-PoP business IPs
				//      that cn.txt already covers (the cascade self-corrects).
				//
				// Why one set, not two: the cn-access preset on existing client
				// binaries expands to [cn-sites, geoip-cn]. If anchor IPs lived in
				// a separate set, no current binary would reference it and the
				// fix would only ship with the next k2 release. Merging into
				// geoip-cn makes every k2 client pick it up on the next daily
				// bundle refresh, with zero client-side change. The blended
				// semantics (HK Tencent PoPs in "geoip-cn") are accepted here
				// in exchange for the deployment-velocity win — see the doc
				// comment in preresolve.go for the full cascade rationale.
				Name:                    "geoip-cn",
				IPURLs:                  []string{"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt"},
				PreResolveV2flyCategory: "category-httpdns-cn",
			},
			{
				Name: "cn-sites",
				V2flyNames: []string{
					"geolocation-cn", "tld-cn",
					// Orphan files: Chinese services not in geolocation-cn.
					"cnb", "coding", "discuz", "dnspod", "duowan", "mocha",
					// Orphan files: global infrastructure accessible from China.
					"amp", "apple-intelligence", "cloudns", "connectivity-check",
					"dynu", "electron", "google-registry-tld", "jquery", "kernel",
					"linux", "nodejs", "noip", "ookla-speedtest", "openjsfoundation",
					"openspeedtest",
					// Orphan files: brands and services accessible from China.
					"2kgames", "adjust", "aerogard", "airwick", "aparat", "archive",
					"asobo", "aviasales", "bethesda", "calgoncarbon", "clearasil",
					"clearbit", "dettol", "divar", "durex", "enfa", "filimo",
					"finish", "forza", "idg", "illusion", "kodik", "lumion",
					"lysol", "meadjohnson", "mihoyo", "mojang", "mortein",
					"mosmetro", "movefree", "mucinex", "newegg", "nurofen",
					"ogury", "openx",
				},
				ExcludeAttr: "!cn", // exclude overseas variants (hk.weibo.com, jd.hk)
			},
		},
	},

	// Iran — v2fly has 16 category-ir files + tld-ir. bootmortis iran-hosted-domains
	// is a curated list of Iranian-hosted services (banks, government, telecom).
	{
		Code: "ir", Name: "Iran",
		Services: []service{
			{
				Name:   "geoip-ir",
				IPURLs: []string{"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/ir.txt"},
			},
			{
				Name: "ir-sites",
				V2flyNames: []string{
					"category-ir", // v2fly has category-ir but no tld-ir
				},
				DomainListURLs: []string{
					// bootmortis iran-hosted-domains: ~130k curated Iranian-hosted domains.
					// Ships via GitHub releases (daily-ish), not raw. The /latest/download/
					// redirect resolves to the current release asset.
					"https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/domains.txt",
				},
				CitizenLabCSVURL: "https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/ir.csv",
			},
			{
				// Reserved for a future privacy/force-proxy mode. Currently unused by engine.
				Name:             "ir-blocked",
				CitizenLabCSVURL: "https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/ir.csv",
			},
		},
	},

	// Russia — v2fly has tld-ru + category-ru + 9 sub-categories. runetfreedom
	// mirrors the RKN official registry every 6h (88k+ CIDRs) and is fed into ru-blocked.
	{
		Code: "ru", Name: "Russia",
		Services: []service{
			{
				Name:   "geoip-ru",
				IPURLs: []string{"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/ru.txt"},
			},
			{
				Name: "ru-sites",
				V2flyNames: []string{
					"tld-ru",
					"category-ru",
				},
				CitizenLabCSVURL: "https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/ru.csv",
			},
			{
				// Reserved for future privacy/force-proxy mode. RU-blocked has the
				// strongest data of any country: runetfreedom + RKN registry.
				Name:             "ru-blocked",
				CitizenLabCSVURL: "https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/ru.csv",
				DomainListURLs: []string{
					// runetfreedom/russia-blocked-geosite: ~75k curated blocked domains
					// from the RKN registry, updated every 6 hours. Uses domain: prefix
					// format (stripped by fetchDomainList).
					"https://github.com/runetfreedom/russia-blocked-geosite/releases/latest/download/ru-blocked.txt",
				},
				IPURLs: []string{
					"https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/text/ru-blocked.txt",
				},
			},
		},
	},

	// Turkey — no v2fly coverage, citizenlab + geoip only.
	{Code: "tr", Name: "Turkey", Services: citizenlabBasic("tr")},

	// Pakistan
	{Code: "pk", Name: "Pakistan", Services: citizenlabBasic("pk")},

	// Vietnam
	{Code: "vn", Name: "Vietnam", Services: citizenlabBasic("vn")},

	// Myanmar — v2fly has category-bank-mm for Myanmar banks (rare but useful).
	{
		Code: "mm", Name: "Myanmar",
		Services: []service{
			{
				Name:   "geoip-mm",
				IPURLs: []string{"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/mm.txt"},
			},
			{
				Name:             "mm-sites",
				V2flyNames:       []string{"category-bank-mm"},
				CitizenLabCSVURL: "https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/mm.csv",
				OrphanDomains:    []string{"mm"},
			},
		},
	},

	// Egypt
	{Code: "eg", Name: "Egypt", Services: citizenlabBasic("eg")},

	// Indonesia
	{Code: "id", Name: "Indonesia", Services: citizenlabBasic("id")},

	// Saudi Arabia
	{Code: "sa", Name: "Saudi Arabia", Services: citizenlabBasic("sa")},

	// United Arab Emirates
	{Code: "ae", Name: "United Arab Emirates", Services: citizenlabBasic("ae")},

	// Thailand
	{Code: "th", Name: "Thailand", Services: citizenlabBasic("th")},

	// Bangladesh
	{Code: "bd", Name: "Bangladesh", Services: citizenlabBasic("bd")},

	// Belarus
	{Code: "by", Name: "Belarus", Services: citizenlabBasic("by")},

	// Turkmenistan — world's 2nd most censored country with internet access
	// (Freedom House 8/100). Single state ISP, VPN use criminalized.
	{Code: "tm", Name: "Turkmenistan", Services: citizenlabBasic("tm")},

	// Kazakhstan — DPI censorship, attempted state CA MITM in 2019/2020.
	{Code: "kz", Name: "Kazakhstan", Services: citizenlabBasic("kz")},

	// Uzbekistan — significant censorship of political/media content.
	{Code: "uz", Name: "Uzbekistan", Services: citizenlabBasic("uz")},
}

// tencentOverseasServices builds the tencent-overseas.krs standalone bundle:
// the full AS132203 (TENCENT-NET-AP-CN) CIDR list — Tencent's overseas PoPs
// (Singapore/HK/JP). Pure data, no action: the client references this set by
// name (match.names) and assigns `reject` ONLY in cn-bypass mode, so the app
// fails over to mainland Tencent IPs (which the cn-direct route routes direct).
// Standalone (not a set inside cn.krs) so region:'cn' expansion does NOT sweep
// it into the direct route. Ships unfiltered; route order does the mainland
// carve-out (geoip-cn wins direct first). See docs/superpowers/plans for the
// full rationale (WeChat HTTPDNS cross-border routing fix).
var tencentOverseasServices = []service{
	{
		Name:   "tencent-overseas",
		IPURLs: []string{"https://raw.githubusercontent.com/ipverse/asn-ip/master/as/132203/ipv4-aggregated.txt"},
	},
}

// tencentOverseasAnchors are the observed overseas-Tencent business IPs that
// triggered the WeChat HTTPDNS cross-border routing problem. The daily build
// asserts AS132203 still covers them (validateTencentOverseas) so an upstream
// format change or ASN re-allocation fails CI loudly instead of shipping a
// reject set that silently no longer matches the IPs we care about.
var tencentOverseasAnchors = []string{"43.159.235.61", "43.153.236.237"}

// citizenlabBasic returns the default two-service recipe for a country with
// no v2fly coverage: geoip + citizenlab CSV. Used for the long tail of
// Tier 1/2 countries where curated open-source data is sparse.
func citizenlabBasic(cc string) []service {
	return []service{
		{
			Name:   "geoip-" + cc,
			IPURLs: []string{"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/" + cc + ".txt"},
		},
		{
			Name:             cc + "-sites",
			CitizenLabCSVURL: "https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/" + cc + ".csv",
			OrphanDomains:    []string{cc}, // ccTLD suffix → all .{cc} domains go direct
		},
	}
}
