package main

// service defines an upstream data source for a rule set.
type service struct {
	Name string

	// Domain sources: v2fly/domain-list-community data/{name} files.
	// Each entry is a v2fly service name (may differ from Name).
	V2flyNames []string

	// IP sources: URLs returning one CIDR per line (plain text).
	IPURLs []string
}

// services defines all rule sets to compile.
// Organized by company/infrastructure, not individual product.
var services = []service{
	{
		Name:       "google",
		V2flyNames: []string{"google", "youtube"},
		IPURLs: []string{
			"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/google.txt",
		},
	},
	{
		Name:       "facebook",
		V2flyNames: []string{"facebook", "whatsapp", "instagram", "meta"},
		IPURLs: []string{
			"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/facebook.txt",
		},
	},
	{
		Name:       "telegram",
		V2flyNames: []string{"telegram"},
		IPURLs: []string{
			"https://core.telegram.org/resources/cidr.txt",
			"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/telegram.txt",
		},
	},
	{
		Name:       "twitter",
		V2flyNames: []string{"twitter"},
		IPURLs: []string{
			"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/twitter.txt",
		},
	},
	{
		Name:       "netflix",
		V2flyNames: []string{"netflix"},
		IPURLs: []string{
			"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/netflix.txt",
		},
	},
	{
		Name:       "cloudflare",
		V2flyNames: nil, // IP-only
		IPURLs: []string{
			"https://www.cloudflare.com/ips-v4",
			"https://www.cloudflare.com/ips-v6",
		},
	},
	{
		Name:       "fastly",
		V2flyNames: nil,
		IPURLs: []string{
			"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/fastly.txt",
		},
	},
	{
		Name:       "discord",
		V2flyNames: []string{"discord"},
	},
	{
		Name:       "spotify",
		V2flyNames: []string{"spotify"},
	},
	{
		Name:       "tiktok",
		V2flyNames: []string{"tiktok"},
	},
	{
		Name:       "openai",
		V2flyNames: []string{"openai"},
	},
	{
		Name:       "github",
		V2flyNames: []string{"github"},
	},
}

// cnServices defines China-specific rule sets.
var cnServices = []service{
	{
		Name:       "geoip-cn",
		V2flyNames: nil,
		IPURLs: []string{
			"https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt",
		},
	},
	{
		Name:       "cn-sites",
		V2flyNames: []string{"cn", "bilibili", "baidu", "tencent", "alibaba", "zhihu", "bytedance"},
	},
	{
		Name:       "bilibili",
		V2flyNames: []string{"bilibili"},
	},
}
