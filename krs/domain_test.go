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
