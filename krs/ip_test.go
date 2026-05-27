package krs_test

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/kaitu-io/k2-rules/krs"
)

// Byte-exact: one set with one IPv4 CIDR emits SetTable + IPv4RangesBySet.
// Entry: u16(set_idx=0) + 4 bytes start + 4 bytes end, network byte order.
func TestWriteBundle_IPv4_OneCIDR(t *testing.T) {
	var buf bytes.Buffer
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "google", CIDRs: []string{"8.8.8.0/24"}},
	}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	want := []byte{
		// Header
		'K', '2', 'R', 'L', 0x01, 0x00, 0x02, 0x00,
		// Index entry 0: SetTable (0x0001), off=28, len=9
		0x01, 0x00, 28, 0, 0, 0, 9, 0, 0, 0,
		// Index entry 1: IPv4RangesBySet (0x0010), off=37, len=10
		0x10, 0x00, 37, 0, 0, 0, 10, 0, 0, 0,
		// SetTable
		0x01, 0x00, 6, 'g', 'o', 'o', 'g', 'l', 'e',
		// IPv4: set_idx=0, start=8.8.8.0, end=8.8.8.255
		0x00, 0x00, 8, 8, 8, 0, 8, 8, 8, 255,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteBundle ipv4:\n got: %x\nwant: %x", buf.Bytes(), want)
	}
}

// Round-trip: write a set with IPv4 + IPv6 CIDRs, read it back, MatchIP
// returns true for in-range addresses and false for out-of-range.
func TestMatchIP_BasicRanges(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{
			Name: "mixed",
			CIDRs: []string{
				"8.8.8.0/24",   // IPv4: 8.8.8.0 – 8.8.8.255
				"1.2.3.4/32",   // IPv4: single host
				"2001:db8::/32", // IPv6
			},
		},
	}}
	got := roundTrip(t, b)
	set := &got.Sets[0]

	hits := []string{
		"8.8.8.0", "8.8.8.128", "8.8.8.255",
		"1.2.3.4",
		"2001:db8::1", "2001:db8:ffff:ffff::",
	}
	misses := []string{
		"8.8.7.255", "8.8.9.0",
		"1.2.3.3", "1.2.3.5",
		"2001:db9::", "2001:db7:ffff:ffff::",
		"127.0.0.1",
	}
	for _, h := range hits {
		addr := netip.MustParseAddr(h)
		if !set.MatchIP(addr) {
			t.Errorf("MatchIP(%s) = false, want true", h)
		}
	}
	for _, m := range misses {
		addr := netip.MustParseAddr(m)
		if set.MatchIP(addr) {
			t.Errorf("MatchIP(%s) = true, want false", m)
		}
	}
}

// /0 prefix matches every address in the family. Boundary edge case for
// the writer's host-bit-fill arithmetic and the binary-search Contains path.
func TestMatchIP_PrefixZeroMatchesAll(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "v4all", CIDRs: []string{"0.0.0.0/0"}},
		{Name: "v6all", CIDRs: []string{"::/0"}},
	}}
	got := roundTrip(t, b)

	v4 := &got.Sets[0]
	for _, h := range []string{"0.0.0.0", "1.2.3.4", "255.255.255.255"} {
		if !v4.MatchIP(netip.MustParseAddr(h)) {
			t.Errorf("v4all MatchIP(%s) = false, want true", h)
		}
	}
	v6 := &got.Sets[1]
	for _, h := range []string{"::", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if !v6.MatchIP(netip.MustParseAddr(h)) {
			t.Errorf("v6all MatchIP(%s) = false, want true", h)
		}
	}
}

// An IPv4 address presented as an IPv4-mapped IPv6 (::ffff:a.b.c.d) must
// still match the v4 routing set. MatchIP unmaps before checking the v4
// section. Real-world: dual-stack sockets surface accepted v4 connections
// as ::ffff:... and routing decisions must agree.
func TestMatchIP_FourInSix(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "google", CIDRs: []string{"8.8.8.0/24"}},
	}}
	got := roundTrip(t, b)
	set := &got.Sets[0]

	mapped := netip.MustParseAddr("::ffff:8.8.8.42")
	if !set.MatchIP(mapped) {
		t.Errorf("MatchIP(::ffff:8.8.8.42) = false, want true (4-in-6)")
	}
	missMapped := netip.MustParseAddr("::ffff:9.9.9.9")
	if set.MatchIP(missMapped) {
		t.Errorf("MatchIP(::ffff:9.9.9.9) = true, want false (4-in-6 miss)")
	}
}

// Strict overlap (not just adjacency): 8.8.0.0/16 contains 8.8.8.0/24.
// mergeRanges must fold them into a single range — otherwise binary search
// still works but redundant entries bloat the bundle.
func TestMatchIP_OverlappingRangesMerge(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{
			Name:  "outer",
			CIDRs: []string{"8.8.0.0/16", "8.8.8.0/24"},
		},
	}}
	got := roundTrip(t, b)
	set := &got.Sets[0]

	for _, h := range []string{"8.8.0.0", "8.8.8.42", "8.8.255.255"} {
		if !set.MatchIP(netip.MustParseAddr(h)) {
			t.Errorf("MatchIP(%s) = false, want true", h)
		}
	}
	if set.MatchIP(netip.MustParseAddr("8.9.0.0")) {
		t.Error("MatchIP(8.9.0.0) = true, want false")
	}
}

// Adjacent CIDRs merge into a single range so the binary search remains
// O(log N) on the natural number of routing intents, not the input count.
func TestMatchIP_AdjacentRangesMerge(t *testing.T) {
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{
			Name: "merged",
			// 10.0.0.0/24 and 10.0.1.0/24 are adjacent — should merge
			// into 10.0.0.0 – 10.0.1.255 (one range, not two).
			CIDRs: []string{"10.0.0.0/24", "10.0.1.0/24"},
		},
	}}
	got := roundTrip(t, b)
	set := &got.Sets[0]

	for _, h := range []string{"10.0.0.0", "10.0.0.255", "10.0.1.0", "10.0.1.255"} {
		if !set.MatchIP(netip.MustParseAddr(h)) {
			t.Errorf("MatchIP(%s) = false, want true", h)
		}
	}
	if set.MatchIP(netip.MustParseAddr("10.0.2.0")) {
		t.Error("MatchIP(10.0.2.0) = true, want false")
	}
}
