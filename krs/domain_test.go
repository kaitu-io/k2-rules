package krs_test

import (
	"bytes"
	"testing"

	"github.com/kaitu-io/k2-rules/krs"
)

// MatchDomain implements suffix-match semantics:
//
//	rule "google.com" matches "google.com" and "*.google.com"
//	but NOT "fakegoogle.com"
func TestMatchDomain_SuffixSemantics(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "google", DomainSuffixes: []string{"google.com"}},
	}}
	got := roundTrip(t, b)
	set := &got.Sets[0]

	cases := []struct {
		host string
		want bool
	}{
		{"google.com", true},
		{"mail.google.com", true},
		{"a.b.google.com", true},
		{"GOOGLE.com", true},      // case-insensitive match
		{"fakegoogle.com", false}, // not a real suffix boundary
		{"google.co", false},
		{"example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := set.MatchDomain(tc.host); got != tc.want {
			t.Errorf("MatchDomain(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// ExcludeDomains override DomainSuffixes: a host matching exclude is rejected
// even when it would otherwise hit a suffix rule.
func TestMatchDomain_ExcludeOverridesInclude(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{
			Name:           "weibo",
			DomainSuffixes: []string{"weibo.com"},
			ExcludeDomains: []string{"hk.weibo.com"},
		},
	}}
	got := roundTrip(t, b)
	set := &got.Sets[0]

	if !set.MatchDomain("weibo.com") {
		t.Error("MatchDomain(weibo.com) = false, want true")
	}
	if !set.MatchDomain("api.weibo.com") {
		t.Error("MatchDomain(api.weibo.com) = false, want true")
	}
	if set.MatchDomain("hk.weibo.com") {
		t.Error("MatchDomain(hk.weibo.com) = true (excluded), want false")
	}
	if set.MatchDomain("m.hk.weibo.com") {
		t.Error("MatchDomain(m.hk.weibo.com) = true (under exclude suffix), want false")
	}
}

// When a set contains both a parent suffix and one or more descendant
// suffixes, parent matches must still resolve correctly for unrelated
// children. Reproduces the "single binary-search misses parent because
// a sibling sub-suffix sits between parent and query in lex order" bug.
//
// Example: rq for "mp.weixin.qq.com" is "moc.qq.nixiew.pm". The reversed
// form of "cgi.weixin.qq.com" is "moc.qq.nixiew.igc", which sorts strictly
// between the parent "moc.qq.nixiew" and the query. A single
// SearchStrings lands on the sibling, HasPrefix fails, parent is missed.
func TestMatchDomain_ParentAndChildCoexist(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{
			Name: "cn-sites",
			DomainSuffixes: []string{
				"weixin.qq.com",
				"cgi.weixin.qq.com",
				"api.weixin.qq.com",
				"open.weixin.qq.com",
			},
		},
	}}
	got := roundTrip(t, b)
	set := &got.Sets[0]

	cases := []struct {
		host string
		want bool
	}{
		{"weixin.qq.com", true},
		{"cgi.weixin.qq.com", true},
		{"api.weixin.qq.com", true},
		{"open.weixin.qq.com", true},
		// Real-world case from production: WeChat MP. The parent rule
		// weixin.qq.com must match even though sibling sub-suffixes
		// (cgi/api/open) sit lex-between parent and query.
		{"mp.weixin.qq.com", true},
		// Same shape: deep grandchild under parent rule.
		{"a.b.weixin.qq.com", true},
		// Negative control: not a real suffix boundary.
		{"fakeweixin.qq.com", false},
	}
	for _, tc := range cases {
		if got := set.MatchDomain(tc.host); got != tc.want {
			t.Errorf("MatchDomain(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// Golden-shape test mirroring real cn-sites composition: a top-level
// parent rule (qq.com, taobao.com, etc.) sitting alongside many sibling
// sub-suffix rules in the same set. Probes high-value production hosts
// that were silently mis-routed under the previous single-binsearch
// algorithm (verified against a real cn.krs build: 12/12 of these
// leaked CN traffic out of the cn-sites routing set).
func TestMatchDomain_HighValueChineseHosts(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{
			Name: "cn-sites",
			DomainSuffixes: []string{
				// Top-level parents.
				"qq.com",
				"taobao.com",
				"meituan.com",
				"tbcache.com",
				// Sibling sub-suffix rules under qq.com that sort
				// lex-between parent "qq.com" and the queried hosts.
				// Even one such sibling is enough to break the old
				// single-binsearch algorithm.
				"cgi.qq.com",
				"gtimg.qq.com",
				"imtt.qq.com",
				"map.qq.com",
				// Sub-suffix rules under taobao.com / meituan.com.
				"alicdn.taobao.com",
				"login.taobao.com",
				"i.meituan.com",
			},
		},
	}}
	got := roundTrip(t, b)
	set := &got.Sets[0]

	hits := []string{
		// WeChat platforms (also exercises the deeper grandchild path
		// where parent is qq.com and host has 4 labels).
		"mp.weixin.qq.com",
		"open.weixin.qq.com",
		"work.weixin.qq.com",
		// Tencent direct subdomains.
		"mp.qq.com",
		"pay.qq.com",
		"video.qq.com",
		"y.qq.com",
		// Alibaba.
		"shop.taobao.com",
		"item.taobao.com",
		"www.tbcache.com",
		// Meituan.
		"mp.meituan.com",
		"www.meituan.com",
	}
	for _, h := range hits {
		if !set.MatchDomain(h) {
			t.Errorf("MatchDomain(%q) = false, want true (production-critical host)", h)
		}
	}

	// Negative controls: not under any parent rule, must not hit.
	misses := []string{
		"example.com",
		"fakeqq.com",
		"qqfake.com",
	}
	for _, h := range misses {
		if set.MatchDomain(h) {
			t.Errorf("MatchDomain(%q) = true, want false", h)
		}
	}
}

// Excludes ride the same domainSection.Match code path as includes, so
// the same parent+sibling bug class can hide here. This locks the fix.
//
// Without the parent-walk fix: an exclude bundle with {weibo.com,
// hk.weibo.com} would correctly catch "hk.weibo.com" but miss "any
// other subdomain.weibo.com" because hk.weibo.com sits lex-between
// weibo.com and the query, masking the parent.
func TestMatchDomain_ExcludeParentAndChildCoexist(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{
			Name:           "blocklist",
			DomainSuffixes: []string{"weibo.com"},
			ExcludeDomains: []string{
				"weibo.com",
				"hk.weibo.com",
				"api.weibo.com",
				"cgi.weibo.com",
			},
		},
	}}
	got := roundTrip(t, b)
	set := &got.Sets[0]

	// All hosts under the include rule "weibo.com" are also excluded
	// (because exclude has a "weibo.com" parent). MatchDomain must
	// return false uniformly.
	mustExclude := []string{
		"weibo.com",
		"hk.weibo.com",
		"api.weibo.com",
		"cgi.weibo.com",
		"mp.weibo.com",
		"open.weibo.com",
		"www.weibo.com",
		"a.b.weibo.com",
	}
	for _, h := range mustExclude {
		if set.MatchDomain(h) {
			t.Errorf("MatchDomain(%q) = true, want false (exclude parent should mask everything)", h)
		}
	}
}

// Each NamedSet must have isolated routing state. A host matching set A's
// rules must NOT match set B unless B has its own covering rule. Locks the
// writer↔reader set_idx handling: a regression that crossed entries from
// one set into another (e.g., dropping the u16 set_idx prefix, or sorting
// without preserving set boundaries) would surface here.
func TestMatchDomain_MultiSetIsolation(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{
			Name:           "cn-sites",
			DomainSuffixes: []string{"qq.com", "taobao.com"},
			ExcludeDomains: []string{"hk.qq.com"},
		},
		{
			Name:           "google",
			DomainSuffixes: []string{"google.com", "youtube.com"},
			ExcludeDomains: []string{"localized.google.com"},
		},
		{
			Name:           "empty",
			DomainSuffixes: nil,
			ExcludeDomains: nil,
		},
	}}
	got := roundTrip(t, b)
	cn := &got.Sets[0]
	g := &got.Sets[1]
	empty := &got.Sets[2]

	// cn-sites hits its own rules, misses google's.
	cases := []struct {
		set     *krs.NamedSet
		setName string
		host    string
		want    bool
	}{
		{cn, "cn-sites", "qq.com", true},
		{cn, "cn-sites", "mp.qq.com", true},
		{cn, "cn-sites", "taobao.com", true},
		{cn, "cn-sites", "hk.qq.com", false}, // excluded
		{cn, "cn-sites", "google.com", false}, // not its rule
		{cn, "cn-sites", "youtube.com", false},
		{cn, "cn-sites", "localized.google.com", false},

		{g, "google", "google.com", true},
		{g, "google", "mail.google.com", true},
		{g, "google", "youtube.com", true},
		{g, "google", "localized.google.com", false}, // excluded
		{g, "google", "qq.com", false}, // not its rule
		{g, "google", "taobao.com", false},
		{g, "google", "hk.qq.com", false},

		// Empty set must reject everything, even hosts other sets accept.
		{empty, "empty", "qq.com", false},
		{empty, "empty", "google.com", false},
		{empty, "empty", "anything.example", false},
	}
	for _, tc := range cases {
		if got := tc.set.MatchDomain(tc.host); got != tc.want {
			t.Errorf("set %q MatchDomain(%q) = %v, want %v", tc.setName, tc.host, got, tc.want)
		}
	}
}

// Algebraic invariant: adding rules that are already descendants of an
// existing parent rule must not change the set's matching behavior. This
// is the property the OLD single-binsearch algorithm violated.
//
// Compare a "minimal" bundle (parent rule only) against a "noisy" bundle
// (parent rule + many descendant rules + unrelated rules) across an
// exhaustive sweep of synthetic host shapes. Mismatch on any host = bug.
func TestMatchDomain_RedundancyEquivalenceProperty(t *testing.T) {
	parents := []string{"qq.com", "taobao.com", "google.com", "example.cn"}

	// Descendants generated deterministically. The first-label prefixes
	// span the alphabet so siblings lex-bracket arbitrary query forms.
	descendantPrefixes := []string{
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
		"n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
		"www", "api", "static", "cdn", "img", "video",
		"sub.deeper",
	}
	queryPrefixes := append([]string{"", "mp", "z", "zzz", "openid"}, descendantPrefixes...)

	var minimalRules []string
	var noisyRules []string
	minimalRules = append(minimalRules, parents...)
	noisyRules = append(noisyRules, parents...)
	for _, p := range parents {
		for _, d := range descendantPrefixes {
			noisyRules = append(noisyRules, d+"."+p)
		}
	}
	// Unrelated rules in the same set — must not contaminate parent coverage.
	noisyRules = append(noisyRules, "unrelated.example", "completely.different.tld")

	minimalBundle := roundTrip(t, &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "set", DomainSuffixes: minimalRules},
	}})
	noisyBundle := roundTrip(t, &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "set", DomainSuffixes: noisyRules},
	}})

	mismatches := 0
	for _, parent := range parents {
		for _, q := range queryPrefixes {
			host := parent
			if q != "" {
				host = q + "." + parent
			}
			a := minimalBundle.Sets[0].MatchDomain(host)
			b := noisyBundle.Sets[0].MatchDomain(host)
			// Sub-suffix-only queries (e.g., "unrelated.example") would
			// short-circuit since they're not under any parent we're
			// iterating; only iterate under known parents above so the
			// invariant we want is: noisy ⊇ minimal (and for parent-
			// covered hosts: equal).
			if a != b {
				t.Errorf("redundancy non-equivalence: host=%q minimal=%v noisy=%v",
					host, a, b)
				mismatches++
				if mismatches > 10 {
					t.Fatalf("too many mismatches — stopping")
				}
			}
			if !a {
				t.Errorf("minimal bundle missed host=%q covered by parent=%q", host, parent)
			}
		}
	}

	// Negative side of the invariant: noisy bundle does NOT match hosts
	// outside its parent rules (no false-positive bleed from unrelated rules).
	negatives := []string{
		"fakeqq.com", "qq.com.evil", "example.com", "different.tld",
	}
	for _, h := range negatives {
		if noisyBundle.Sets[0].MatchDomain(h) {
			t.Errorf("noisy bundle false-positive on host=%q", h)
		}
	}
}

// FQDN trailing-dot tolerance. Real DNS responses can surface a host as
// "weibo.com." — Match must treat the dotless and dotted forms identically
// so callers do not have to normalize. Documenting the contract here.
func TestMatchDomain_TrailingDotTolerated(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{
			Name:           "set",
			DomainSuffixes: []string{"weibo.com"},
			ExcludeDomains: []string{"hk.weibo.com"},
		},
	}}
	got := roundTrip(t, b)
	set := &got.Sets[0]

	cases := []struct {
		host string
		want bool
	}{
		{"weibo.com", true},
		{"weibo.com.", true}, // FQDN form
		{"WEIBO.COM.", true}, // FQDN + uppercase
		{"mail.weibo.com", true},
		{"mail.weibo.com.", true},
		{"hk.weibo.com", false},
		{"hk.weibo.com.", false},
		{"fakeweibo.com.", false},
		{".", false}, // pathological but should not crash
	}
	for _, tc := range cases {
		if got := set.MatchDomain(tc.host); got != tc.want {
			t.Errorf("MatchDomain(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func roundTrip(t *testing.T, in *krs.Bundle) *krs.Bundle {
	t.Helper()
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, in); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	out, err := krs.ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	return out
}
