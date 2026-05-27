package krs_test

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/kaitu-io/k2-rules/krs"
)

// An empty bundle (no sets, no apps) should serialize to exactly the
// 8-byte header: magic + version + section count.
func TestWriteBundle_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, &krs.Bundle{}); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	want := []byte{
		'K', '2', 'R', 'L',
		0x01, 0x00,
		0x00, 0x00,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteBundle empty:\n got: %x\nwant: %x", buf.Bytes(), want)
	}
}

// One named set with no data emits only a SetTable section.
// Layout:
//
//	[8B hdr] [10B index entry: TypeID=0x0001, off=18, len=9]
//	[9B SetTable: count=1, uvarint(6), "google"]
func TestWriteBundle_OneSet_NoData(t *testing.T) {
	var buf bytes.Buffer
	b := &krs.Bundle{Sets: []krs.NamedSet{{Name: "google"}}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	want := []byte{
		// Header
		'K', '2', 'R', 'L',
		0x01, 0x00,
		0x01, 0x00, // section count = 1
		// Index entry [TypeID=0x0001, off=18, len=9]
		0x01, 0x00,
		18, 0, 0, 0,
		9, 0, 0, 0,
		// SetTable payload: count=1, uvarint(6), "google"
		0x01, 0x00,
		6,
		'g', 'o', 'o', 'g', 'l', 'e',
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteBundle one-set:\n got: %x\nwant: %x", buf.Bytes(), want)
	}
}

// One set with one domain emits SetTable + DomainSuffixBySet, both in
// TypeID-ascending order. Domain is reversed and lowercased at compile time.
//
// Layout:
//
//	[8B hdr] [10B SetTable index] [10B DomainSuffix index]
//	[SetTable: u16(1) + uvarint(6) + "google"] = 9B
//	[DomainSuffix: u16(set_idx=0) + uvarint(10) + "moc.elgoog"] = 13B
func TestWriteBundle_DomainSuffix(t *testing.T) {
	var buf bytes.Buffer
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "google", DomainSuffixes: []string{"google.com"}},
	}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	want := []byte{
		// Header
		'K', '2', 'R', 'L', 0x01, 0x00, 0x02, 0x00,
		// Index entry 0: SetTable (0x0001), off=28, len=9
		0x01, 0x00, 28, 0, 0, 0, 9, 0, 0, 0,
		// Index entry 1: DomainSuffixBySet (0x0012), off=37, len=13
		0x12, 0x00, 37, 0, 0, 0, 13, 0, 0, 0,
		// SetTable payload
		0x01, 0x00, 6, 'g', 'o', 'o', 'g', 'l', 'e',
		// DomainSuffix payload: set_idx=0, uvarint(10), "moc.elgoog"
		0x00, 0x00, 10, 'm', 'o', 'c', '.', 'e', 'l', 'g', 'o', 'o', 'g',
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteBundle domain-suffix:\n got: %x\nwant: %x", buf.Bytes(), want)
	}
}

// Mixed-case domains are lowercased before reversing. Mixed order is sorted
// by (set_idx ASC, value ASC) on the reversed-lower form.
func TestWriteBundle_DomainSuffix_SortsAndLowers(t *testing.T) {
	var buf bytes.Buffer
	// Two sets, second listed first to confirm set_idx follows Sets[] order.
	// Domains in non-sorted, mixed-case order to confirm normalization.
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "alpha", DomainSuffixes: []string{"B.com", "a.com"}},
		{Name: "beta", DomainSuffixes: []string{"C.com"}},
	}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	// After normalization & sort: alpha → [moc.a, moc.b], beta → [moc.c]
	// (entries: set_idx ASC, then reversed-lower string ASC)
	got := buf.Bytes()
	// Find the DomainSuffix section payload by looking at index entry 1.
	if got[18] != 0x12 {
		t.Fatalf("expected DomainSuffix at index[1], got TypeID=0x%02x%02x", got[19], got[18])
	}
	off := int(binary.LittleEndian.Uint32(got[20:24]))
	length := int(binary.LittleEndian.Uint32(got[24:28]))
	payload := got[off : off+length]

	wantPayload := []byte{
		// (set_idx=0, "moc.a")
		0x00, 0x00, 5, 'm', 'o', 'c', '.', 'a',
		// (set_idx=0, "moc.b")
		0x00, 0x00, 5, 'm', 'o', 'c', '.', 'b',
		// (set_idx=1, "moc.c")
		0x01, 0x00, 5, 'm', 'o', 'c', '.', 'c',
	}
	if !bytes.Equal(payload, wantPayload) {
		t.Errorf("DomainSuffix payload:\n got: %x\nwant: %x", payload, wantPayload)
	}
}

// Writer must be deterministic — repeated writes of the same Bundle, and
// writes of semantically equivalent Bundles (rules in different input
// order), must produce byte-identical output. CI release-skip logic
// compares SHA256s across daily builds; nondeterminism would force
// spurious releases.
func TestWriteBundle_Deterministic(t *testing.T) {
	build := func(domainOrder, cidrOrder, appOrder []int) *krs.Bundle {
		domains := []string{"google.com", "youtube.com", "gstatic.com"}
		cidrs := []string{"8.8.8.0/24", "1.1.1.0/24", "9.9.9.0/24"}
		apps := []string{"com.tencent.*", "com.taobao.*", "com.alibaba.*"}
		permute := func(src []string, order []int) []string {
			out := make([]string, len(src))
			for i, idx := range order {
				out[i] = src[idx]
			}
			return out
		}
		return &krs.Bundle{
			Sets: []krs.NamedSet{{
				Name:           "set",
				DomainSuffixes: permute(domains, domainOrder),
				CIDRs:          permute(cidrs, cidrOrder),
			}},
			Apps: &krs.AppPatterns{
				Android: krs.AndroidPatterns{Apps: permute(apps, appOrder)},
			},
		}
	}
	encode := func(b *krs.Bundle) []byte {
		var buf bytes.Buffer
		if err := krs.WriteBundle(&buf, b); err != nil {
			t.Fatalf("WriteBundle: %v", err)
		}
		return buf.Bytes()
	}

	// Repeated writes of the same input.
	a := encode(build([]int{0, 1, 2}, []int{0, 1, 2}, []int{0, 1, 2}))
	b := encode(build([]int{0, 1, 2}, []int{0, 1, 2}, []int{0, 1, 2}))
	if !bytes.Equal(a, b) {
		t.Errorf("same input produced different bytes:\n a=%x\n b=%x", a, b)
	}

	// Semantically equivalent input in permuted order.
	c := encode(build([]int{2, 0, 1}, []int{1, 2, 0}, []int{2, 1, 0}))
	if !bytes.Equal(a, c) {
		t.Errorf("permuted input changed output bytes:\n a=%x\n c=%x", a, c)
	}

	// Duplicated input — should dedup to the same output.
	dupBundle := &krs.Bundle{Sets: []krs.NamedSet{{
		Name:           "set",
		DomainSuffixes: []string{"google.com", "google.com", "youtube.com", "gstatic.com", "youtube.com"},
		CIDRs:          []string{"8.8.8.0/24", "8.8.8.0/24", "1.1.1.0/24", "9.9.9.0/24"},
	}}, Apps: &krs.AppPatterns{
		Android: krs.AndroidPatterns{Apps: []string{"com.tencent.*", "com.tencent.*", "com.taobao.*", "com.alibaba.*"}},
	}}
	d := encode(dupBundle)
	if !bytes.Equal(a, d) {
		t.Errorf("duplicated input did not dedup to canonical form:\n a=%x\n d=%x", a, d)
	}
}

// End-to-end semantic round-trip: a bundle exercising every TypeID currently
// emitted (domains, excludes, IPv4, IPv6, all four app sections) must
// produce identical Match* behavior after Write→Read.
//
// Byte-level round-trip tests would not catch a regression where the reader
// silently drops a section type or misroutes by set_idx — those would still
// produce a parseable Bundle. This test compares actual matching outcomes
// against the input, so any semantic divergence is caught immediately.
func TestRoundTrip_SemanticEquivalence_AllFeatures(t *testing.T) {
	in := &krs.Bundle{
		Sets: []krs.NamedSet{
			{
				Name:           "google",
				DomainSuffixes: []string{"google.com", "youtube.com"},
				ExcludeDomains: []string{"localized.google.com"},
				CIDRs:          []string{"8.8.8.0/24", "2001:db8::/32"},
			},
			{
				Name:           "cn-sites",
				DomainSuffixes: []string{"qq.com", "weixin.qq.com", "taobao.com"},
				ExcludeDomains: []string{"intl.qq.com"},
				CIDRs:          []string{"1.0.0.0/8"},
			},
		},
		Apps: &krs.AppPatterns{
			Android: krs.AndroidPatterns{
				Installers: []string{"com.android.vending"},
				Apps:       []string{"com.tencent.*", "com.taobao.*"},
			},
			Windows: krs.WindowsPatterns{Apps: []string{"wechat*", "qq*"}},
			Darwin:  krs.DarwinPatterns{Apps: []string{"WeChat*", "DingTalk*"}},
		},
	}

	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, in); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	out, err := krs.ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}

	if len(out.Sets) != len(in.Sets) {
		t.Fatalf("set count: in=%d out=%d", len(in.Sets), len(out.Sets))
	}
	for i := range in.Sets {
		if out.Sets[i].Name != in.Sets[i].Name {
			t.Errorf("set[%d].Name: in=%q out=%q", i, in.Sets[i].Name, out.Sets[i].Name)
		}
	}

	// Domain matches.
	domainCases := []struct {
		setIdx     int
		host       string
		want       bool
		annotation string
	}{
		{0, "google.com", true, "google include"},
		{0, "mail.google.com", true, "google subdomain"},
		{0, "youtube.com", true, "second google include"},
		{0, "localized.google.com", false, "google exclude"},
		{0, "subdomain.localized.google.com", false, "exclude subdomain"},
		{0, "qq.com", false, "cn rule not in google set"},
		{1, "qq.com", true, "cn include"},
		{1, "mp.weixin.qq.com", true, "deep child under cn parent"},
		{1, "taobao.com", true, "second cn include"},
		{1, "intl.qq.com", false, "cn exclude"},
		{1, "google.com", false, "google rule not in cn set"},
	}
	for _, tc := range domainCases {
		if got := out.Sets[tc.setIdx].MatchDomain(tc.host); got != tc.want {
			t.Errorf("MatchDomain set[%d]=%s host=%q (%s): got %v want %v",
				tc.setIdx, out.Sets[tc.setIdx].Name, tc.host, tc.annotation, got, tc.want)
		}
	}

	// IP matches.
	ipCases := []struct {
		setIdx int
		addr   string
		want   bool
	}{
		{0, "8.8.8.42", true},
		{0, "8.8.9.0", false},
		{0, "2001:db8::1", true},
		{0, "2001:db9::1", false},
		{0, "1.0.0.1", false}, // cn-sites range, not google
		{1, "1.0.0.1", true},
		{1, "1.255.255.255", true},
		{1, "2.0.0.0", false},
		{1, "8.8.8.42", false}, // google range, not cn-sites
	}
	for _, tc := range ipCases {
		addr := netip.MustParseAddr(tc.addr)
		if got := out.Sets[tc.setIdx].MatchIP(addr); got != tc.want {
			t.Errorf("MatchIP set[%d]=%s addr=%s: got %v want %v",
				tc.setIdx, out.Sets[tc.setIdx].Name, tc.addr, got, tc.want)
		}
	}

	// App pattern matches across platforms.
	if out.Apps == nil {
		t.Fatal("out.Apps is nil after round-trip")
	}
	if pat, ok := out.Apps.MatchAndroidPackage("com.tencent.mm"); !ok || pat != "com.tencent.*" {
		t.Errorf("MatchAndroidPackage(com.tencent.mm): got (%q, %v) want (com.tencent.*, true)", pat, ok)
	}
	if pat, ok := out.Apps.MatchAndroidInstaller("com.android.vending"); !ok || pat != "com.android.vending" {
		t.Errorf("MatchAndroidInstaller: got (%q, %v)", pat, ok)
	}
	if pat, ok := out.Apps.MatchWindowsProcess("WeChat.exe"); !ok || pat != "wechat*" {
		t.Errorf("MatchWindowsProcess(WeChat.exe): got (%q, %v) want (wechat*, true)", pat, ok)
	}
	if pat, ok := out.Apps.MatchDarwinProcess("WeChat Helper"); !ok || pat != "WeChat*" {
		t.Errorf("MatchDarwinProcess(WeChat Helper): got (%q, %v) want (WeChat*, true)", pat, ok)
	}
	// Case sensitivity locked: Darwin must NOT match lowercased input.
	if _, ok := out.Apps.MatchDarwinProcess("wechat"); ok {
		t.Error("MatchDarwinProcess(wechat): matched lowercase, expected case-sensitive miss")
	}
}

// Two sets — names retain caller-supplied order (set_idx 0 → "google", 1 → "youtube").
func TestWriteBundle_TwoSets_PreservesOrder(t *testing.T) {
	var buf bytes.Buffer
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "google"},
		{Name: "youtube"},
	}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	// SetTable payload: 2(count) + 1(uvarint) + 6("google") + 1(uvarint) + 7("youtube") = 17 bytes
	want := []byte{
		'K', '2', 'R', 'L',
		0x01, 0x00,
		0x01, 0x00,
		0x01, 0x00,
		18, 0, 0, 0,
		17, 0, 0, 0,
		0x02, 0x00,
		6, 'g', 'o', 'o', 'g', 'l', 'e',
		7, 'y', 'o', 'u', 't', 'u', 'b', 'e',
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteBundle two-sets:\n got: %x\nwant: %x", buf.Bytes(), want)
	}
}
