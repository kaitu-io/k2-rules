package krs

import (
	"bytes"
	"testing"
)

func roundTrip(t *testing.T, b *Bundle) *Bundle {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	got, err := ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	return got
}

func TestBundleRuleCount(t *testing.T) {
	got := roundTrip(t, &Bundle{Sets: []NamedSet{
		{Name: "a", DomainSuffixes: []string{"google.com", "youtube.com"}},
		{Name: "b", CIDRs: []string{"8.8.8.0/24", "1.1.1.0/24"}}, // non-adjacent → 2 ranges
	}})
	// 2 domains + 2 distinct CIDR ranges = 4.
	if n := got.RuleCount(); n != 4 {
		t.Errorf("RuleCount() = %d, want 4", n)
	}
}

func TestBundleRuleCount_AdjacentCIDRsMerge(t *testing.T) {
	// 1.0.0.0/24 and 1.0.1.0/24 are adjacent. CONFIRMED: the canonical writer
	// merges adjacent ranges (ip.go: "Ranges are pre-merged on write so the
	// slice is in canonical form: non-overlapping, non-adjacent"), collapsing
	// these two /24s into ONE range. RuleCount counts post-merge ranges → 1.
	got := roundTrip(t, &Bundle{Sets: []NamedSet{
		{Name: "m", CIDRs: []string{"1.0.0.0/24", "1.0.1.0/24"}},
	}})
	if n := got.RuleCount(); n != 1 {
		t.Errorf("adjacent CIDRs RuleCount() = %d, want 1 (merged)", n)
	}
}

func TestBundleRuleCount_ExcludeOnlyIsZero(t *testing.T) {
	// A set with only excludes matches nothing → counts 0 (mirrors IsEmpty).
	got := roundTrip(t, &Bundle{Sets: []NamedSet{
		{Name: "x", ExcludeDomains: []string{"ads.example.com"}},
	}})
	if n := got.RuleCount(); n != 0 {
		t.Errorf("exclude-only RuleCount() = %d, want 0", n)
	}
}

func TestBundleRuleCount_Empty(t *testing.T) {
	if (&Bundle{}).RuleCount() != 0 {
		t.Error("empty bundle RuleCount must be 0")
	}
}
