package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeV2flyData(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func resolveSorted(t *testing.T, dir, spec string) string {
	t.Helper()
	got, err := resolveV2flySelective(dir, spec)
	if err != nil {
		t.Fatalf("resolve %q: %v", spec, err)
	}
	sort.Strings(got)
	return strings.Join(got, ",")
}

func TestResolveV2flySelective(t *testing.T) {
	dir := writeV2flyData(t, map[string]string{
		"vendor": strings.Join([]string{
			"vendor.com",
			"full:ads.vendor.com @ads",
			"domain:track.vendor.com @ads @cn # inline comment",
			"Stats.Vendor.com @telemetry",
			"regexp:^ad[0-9]\\.vendor\\.com$ @ads",
			"keyword:vendorads @ads",
			"affil.vendor.com &other-list @ads",
		}, "\n"),
		"nested":    "include:vendor @ads\nnested-own.com\n",
		"top":       "include:nested\ninclude:vendor @ads @-cn\ntop-own.com @ads\n",
		"whole":     "include:vendor\n",
		"cycle-a":   "include:cycle-b\n",
		"cycle-b":   "include:cycle-a\n",
		"dangling":  "include:does-not-exist @ads\n",
		"duplicate": "include:vendor @ads\ninclude:vendor @ads\n",
	})

	cases := []struct{ spec, want string }{
		// A filtered include takes only the tagged rules, never the vendor's own host.
		{"nested", "ads.vendor.com,affil.vendor.com,nested-own.com,track.vendor.com"},
		// @-attr drops rules carrying it; filters apply through nested includes.
		{"top", "ads.vendor.com,affil.vendor.com,nested-own.com,top-own.com,track.vendor.com"},
		// A filter on the spec itself applies to the whole resolved tree.
		{"top @ads", "ads.vendor.com,affil.vendor.com,top-own.com,track.vendor.com"},
		{"top @ads @-cn", "ads.vendor.com,affil.vendor.com,top-own.com"},
		// An unfiltered include still takes everything; names are lowercased.
		{"whole", "ads.vendor.com,affil.vendor.com,stats.vendor.com,track.vendor.com,vendor.com"},
		{"duplicate", "ads.vendor.com,affil.vendor.com,track.vendor.com"},
	}
	for _, c := range cases {
		if got := resolveSorted(t, dir, c.spec); got != c.want {
			t.Errorf("spec %q:\n got  %s\n want %s", c.spec, got, c.want)
		}
	}

	for _, spec := range []string{"cycle-a", "dangling", "does-not-exist", ""} {
		if _, err := resolveV2flySelective(dir, spec); err == nil {
			t.Errorf("spec %q resolved, want error", spec)
		}
	}
}

func TestAdsServicesShape(t *testing.T) {
	if len(adsServices) != len(adsAnchors) {
		t.Fatalf("%d services but %d anchor groups — a set with no anchors ships unvalidated",
			len(adsServices), len(adsAnchors))
	}
	for _, s := range adsServices {
		if len(s.V2flyNames) != 0 {
			t.Errorf("set %q uses V2flyNames; a rejected set must use V2flySelective", s.Name)
		}
		if len(s.IPURLs) != 0 || s.ComplementIPURL != "" {
			t.Errorf("set %q carries IP sources; ads is domain-only", s.Name)
		}
		if got, want := len(adsAnchors[s.Name]), len(s.V2flySelective); got != want {
			t.Errorf("set %q: %d anchors for %d v2fly specs, want 1:1", s.Name, got, want)
		}
	}
	if len(adsMustNotBlock) == 0 {
		t.Error("adsMustNotBlock is empty — the over-block guard checks nothing")
	}
}

func TestValidateAds(t *testing.T) {
	anchors := map[string][]string{"ads": {"doubleclick.net"}}
	mustNot := []string{"www.google.com", "sentry.io"}

	ok := []bundleSet{{Name: "ads", Domains: []string{"doubleclick.net", "ads.google.com"}}}
	if err := validateAds(ok, anchors, mustNot); err != nil {
		t.Errorf("clean set rejected: %v", err)
	}
	for name, domains := range map[string][]string{
		"missing anchor":  {"ads.google.com"},
		"exact host":      {"doubleclick.net", "sentry.io"},
		"parent suffix":   {"doubleclick.net", "google.com"},
		"bare tld suffix": {"doubleclick.net", "com"},
	} {
		if err := validateAds([]bundleSet{{Name: "ads", Domains: domains}}, anchors, mustNot); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
	if err := validateAds(nil, anchors, mustNot); err == nil {
		t.Error("missing set accepted, want error")
	}
}
