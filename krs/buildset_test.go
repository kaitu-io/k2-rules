package krs

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestBuildSet_DomainsAndIPs(t *testing.T) {
	ns, err := BuildSet(NamedSet{
		Name:           "inline",
		DomainSuffixes: []string{"google.com", "例え.jp"}, // 含 IDN
		CIDRs:          []string{"8.8.8.0/24", "2001:db8::/32"},
	})
	if err != nil {
		t.Fatalf("BuildSet: %v", err)
	}
	var m Matcher = ns // 必须满足 Matcher

	for _, tc := range []struct {
		host string
		want bool
	}{
		{"google.com", true},
		{"www.google.com", true},
		{"notgoogle.com", false},
		{"例え.jp", true},
		{"a.例え.jp", true},
		{"example.org", false},
	} {
		if got := m.MatchDomainReversed(ReversedParents(tc.host)); got != tc.want {
			t.Errorf("MatchDomain(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"8.8.9.1", false},
		{"2001:db8::1", true},
		{"2001:dead::1", false},
	} {
		if got := m.MatchIP(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("MatchIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if ns.IsEmpty() {
		t.Error("IsEmpty = true on a populated set")
	}
}

func TestBuildSet_Excludes(t *testing.T) {
	ns, err := BuildSet(NamedSet{
		DomainSuffixes: []string{"google.com"},
		ExcludeDomains: []string{"ads.google.com"},
	})
	if err != nil {
		t.Fatalf("BuildSet: %v", err)
	}
	if !ns.MatchDomainReversed(ReversedParents("www.google.com")) {
		t.Error("www.google.com should match (suffix)")
	}
	if ns.MatchDomainReversed(ReversedParents("ads.google.com")) {
		t.Error("ads.google.com should be excluded")
	}
}

func TestBuildSet_Empty(t *testing.T) {
	ns, err := BuildSet(NamedSet{Name: "empty"})
	if err != nil {
		t.Fatalf("BuildSet(empty): %v", err)
	}
	if !ns.IsEmpty() {
		t.Error("IsEmpty = false on a set with no rules")
	}
	if ns.MatchDomainReversed(ReversedParents("anything.com")) {
		t.Error("empty set matched a domain")
	}
}

func TestBuildSet_ExcludeOnlyIsEmpty(t *testing.T) {
	// exclude-only 集合匹配空集 → 应视为 empty（不贡献 host criteria）。
	ns, err := BuildSet(NamedSet{ExcludeDomains: []string{"x.com"}})
	if err != nil {
		t.Fatalf("BuildSet(exclude-only): %v", err)
	}
	if !ns.IsEmpty() {
		t.Error("exclude-only set should report IsEmpty = true")
	}
}

func TestBuildSet_AllInvalidDropsToEmpty(t *testing.T) {
	ns, err := BuildSet(NamedSet{
		DomainSuffixes: []string{"_underscore_", "*.wild", "has space"},
		CIDRs:          []string{"not-a-cidr", "999.999.0.0/8"},
	})
	if err != nil {
		t.Fatalf("BuildSet(all-invalid): %v", err)
	}
	if !ns.IsEmpty() {
		t.Error("all-invalid input should drop to IsEmpty = true")
	}
}

func TestBuildSet_ParityWithFileRoundTrip(t *testing.T) {
	s := NamedSet{
		Name:           "p",
		DomainSuffixes: []string{"a.com", "b.org", "xn--r8jz45g.jp"},
		CIDRs:          []string{"10.0.0.0/8", "fd00::/8"},
	}
	built, err := BuildSet(s)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteBundle(&buf, &Bundle{Sets: []NamedSet{s}}); err != nil {
		t.Fatal(err)
	}
	b, err := ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	loaded := Index([]*Bundle{b})["p"]
	for _, h := range []string{"a.com", "x.a.com", "b.org", "c.net", "10.1.2.3", "fd00::1", "8.8.8.8"} {
		if addr, err := netip.ParseAddr(h); err == nil {
			if built.MatchIP(addr) != loaded.MatchIP(addr) {
				t.Errorf("IP parity mismatch at %q", h)
			}
			continue
		}
		rp := ReversedParents(h)
		if built.MatchDomainReversed(rp) != loaded.MatchDomainReversed(rp) {
			t.Errorf("domain parity mismatch at %q", h)
		}
	}
}
