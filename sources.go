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
}

// services defines overseas rule sets (sites blocked in China).
// Uses v2fly/geolocation-!cn (972 files recursive) + orphan blocked sites.
var services = []service{
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

// cnServices defines China-specific rule sets.
// Uses v2fly/geolocation-cn (335 files recursive) + orphan China-accessible sites.
var cnServices = []service{
	{
		Name:       "geoip-cn",
		V2flyNames: nil,
		IPURLs: []string{
			"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt",
		},
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
}
