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

// gamesServices builds the games.krs standalone bundle: game-vendor domains
// (v2fly category-games) plus the vendor ASN CIDR ranges that carry the
// matchmaking and gameplay UDP traffic.
//
// Two sets rather than one because game clients split their traffic: login,
// patching and the store are domain-addressed (games-sites catches those),
// while match servers are reached by bare IP with no DNS lookup at all
// (games-ip is the only thing that can classify those). A single blended set
// would work too, but keeping them apart lets the client route them
// differently — the domain half is safe to treat like any other web traffic,
// the IP half is where the latency-sensitive UDP lives.
//
// ASN list is deliberately short: each entry was individually confirmed to
// resolve to the named vendor (WHOIS org name), not inferred from a
// third-party "gaming ASN" list. Two candidates from the initial brief were
// dropped after verification — AS394699 is ZenFi Networks (not Epic Games)
// and AS11282 is SERVERYOU (not Nintendo) — do not re-add them without
// re-verifying WHOIS ownership first.
//
// Standalone bundle (not a set inside cn.krs) so region expansion does NOT
// sweep games into the direct route.
var gamesServices = []service{
	{
		// "category-games" itself is just "include:category-games-cn" +
		// "include:category-games-!cn" — pulling the whole category also pulls
		// the CN half (Tencent games, miHoYo CN client, 4399, bilibili-game,
		// etc.), and those ~289 domains are already covered by cn-sites for
		// direct routing. If a client applies games routing before cn-direct,
		// that overlap silently strips domestic games away from the direct
		// route and sends them overseas — a real regression for CN users, not
		// a hypothetical one (verified: all 289 CN-half domains already exist
		// in cn-sites). Restricting to the overseas half keeps games-sites
		// purely additive: it only ever adds domains cn-sites doesn't already
		// route, so route ordering can never take a CN domain away from direct.
		Name:       "games-sites",
		V2flyNames: []string{"category-games-!cn"},
	},
	{
		Name: "games-ip",
		IPURLs: []string{
			"https://raw.githubusercontent.com/ipverse/asn-ip/master/as/32590/ipv4-aggregated.txt", // AS32590 Valve Corporation
			"https://raw.githubusercontent.com/ipverse/asn-ip/master/as/6507/ipv4-aggregated.txt",  // AS6507 Riot Games Inc (RIOT-NA1)
			"https://raw.githubusercontent.com/ipverse/asn-ip/master/as/57976/ipv4-aggregated.txt", // AS57976 Blizzard Entertainment Inc
			"https://raw.githubusercontent.com/ipverse/asn-ip/master/as/33353/ipv4-aggregated.txt", // AS33353 Sony Interactive Entertainment LLC (AS-GAIKAI)
		},
	},
}

// gamesAnchors are IPs that games-ip must cover. The daily build fails closed
// if an upstream format change or ASN re-allocation makes the set stop
// matching them — same guard as tencentOverseasAnchors.
//
// INVARIANT — 1:1 with games-ip's IPURLs, one anchor per ASN feed, in the
// same order. validateGames (main.go) only checks that every anchor is
// covered by the union of all CIDRs, not that any specific feed produced any
// specific anchor. If a future ASN is added to IPURLs without a matching
// anchor here, the guard silently degrades from "every vendor ASN feed is
// still alive" to "at least one vendor ASN feed is still alive" — losing 3
// of 4 feeds would no longer fail closed. games_test.go's
// TestGamesServicesShape enforces len(gamesAnchors) == len(IPURLs); keep them
// in lockstep when editing either slice.
//
// IMPORTANT — these are NOT observed game-server IPs (unlike
// tencentOverseasAnchors, which came from a real incident). They are
// placeholders: the first advertised /24 (or narrower) block from each
// ASN's current ipverse/asn-ip aggregated list, as of 2026-08-04, with the
// .1 host picked as a stand-in address. What this anchor set actually
// verifies is narrower than it looks:
//
//   - It DOES verify: "the upstream ipverse/asn-ip feed for this ASN is
//     still reachable and still returns a non-empty range that includes
//     this address" — i.e. the data pipeline for that ASN hasn't silently
//     gone empty or been re-pointed to a different owner.
//   - It does NOT verify: that any of these specific addresses is still a
//     reachable/live game server, or even that the vendor still operates
//     that /24 today beyond what the aggregated list currently states.
//
// Replace each entry with a real, observed game-client-to-server IP (captured
// via `lsof -i UDP` / packet capture during actual gameplay, cross-checked
// against the vendor at https://bgp.tools/) as soon as one is available —
// that upgrades the guard from "feed still shaped like the vendor's block"
// to "the traffic we actually care about is still covered."
var gamesAnchors = []string{
	"45.121.184.1", // AS32590 Valve — placeholder, from 45.121.184.0/24 (asn-ip, 2026-08-04)
	"43.229.64.1",  // AS6507 Riot Games — placeholder, from 43.229.64.0/22 (asn-ip, 2026-08-04)
	"5.42.160.1",   // AS57976 Blizzard — placeholder, from 5.42.160.0/20 (asn-ip, 2026-08-04)
	"69.36.129.1",  // AS33353 Sony/Gaikai — placeholder, from 69.36.129.0/24 (asn-ip, 2026-08-04)
}

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
