package krs

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// writeTmpBundle writes b to a temp .krs and returns its path.
func writeTmpBundle(t *testing.T, b *Bundle) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteBundle(&buf, b); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "b.krs")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOpen_NamesAndClose(t *testing.T) {
	b := &Bundle{Sets: []NamedSet{
		{Name: "cn", DomainSuffixes: []string{"qq.com"}, CIDRs: []string{"1.1.1.0/24"}},
		{Name: "x", DomainSuffixes: []string{"foo.org"}},
	}}
	db, err := Open(writeTmpBundle(t, b))
	if err != nil {
		t.Fatal(err)
	}
	if got := db.SetNames(); len(got) != 2 || got[0] != "cn" || got[1] != "x" {
		t.Fatalf("SetNames=%v", got)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestDiskBundle_ParityWithReadBundle(t *testing.T) {
	b := &Bundle{Sets: []NamedSet{
		{
			Name:           "cn",
			DomainSuffixes: []string{"qq.com", "weixin.qq.com", "taobao.com"},
			ExcludeDomains: []string{"intl.taobao.com"},
			CIDRs:          []string{"1.2.3.0/24", "10.0.0.0/8", "2001:db8::/32"},
		},
		{Name: "os", DomainSuffixes: []string{"google.com"}, CIDRs: []string{"8.8.8.0/24"}},
	}}
	var buf bytes.Buffer
	if err := WriteBundle(&buf, b); err != nil {
		t.Fatal(err)
	}
	heap, err := ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(writeTmpBundle(t, b))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	disk := db.Sets()

	domains := []string{"qq.com", "weixin.qq.com", "a.weixin.qq.com",
		"taobao.com", "intl.taobao.com", "deep.intl.taobao.com",
		"google.com", "evil.com", "qq.com.evil.com"}
	ips := []string{"1.2.3.4", "1.2.4.1", "10.255.0.1", "8.8.8.8", "9.9.9.9",
		"2001:db8::1", "2001:dead::1"}
	for si := range heap.Sets {
		hs := &heap.Sets[si]
		ds := disk[si]
		for _, host := range domains {
			parents := ReversedParents(host)
			if hs.MatchDomainReversed(parents) != ds.MatchDomainReversed(parents) {
				t.Errorf("set %d domain %q: heap=%v disk=%v", si, host,
					hs.MatchDomainReversed(parents), ds.MatchDomainReversed(parents))
			}
		}
		for _, ipStr := range ips {
			addr := netip.MustParseAddr(ipStr)
			if hs.MatchIP(addr) != ds.MatchIP(addr) {
				t.Errorf("set %d ip %q: heap=%v disk=%v", si, ipStr,
					hs.MatchIP(addr), ds.MatchIP(addr))
			}
		}
	}
}

// TestDiskBundle_Parity_IDNAnd4in6 covers two edges the main parity test omits:
// IDN hosts (stored as punycode, queried via ReversedParents' IDNA fold) and
// 4-in-6 addresses (MatchIP must also consult the v4 section). Disk and heap
// readers must agree on both.
func TestDiskBundle_Parity_IDNAnd4in6(t *testing.T) {
	b := &Bundle{Sets: []NamedSet{{
		Name:           "cn",
		DomainSuffixes: []string{"例え.jp", "测试.中国", "ascii.example"},
		CIDRs:          []string{"1.2.3.0/24", "2001:db8::/32"},
	}}}
	var buf bytes.Buffer
	if err := WriteBundle(&buf, b); err != nil {
		t.Fatal(err)
	}
	heap, err := ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(writeTmpBundle(t, b))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	hs := &heap.Sets[0]
	ds := db.Sets()[0]
	for _, host := range []string{
		"例え.jp", "www.例え.jp", "测试.中国", "ascii.example",
		"xn--r8jz45g.jp", // punycode of 例え.jp — must match the same rule
		"notmatched.jp", "例えf.jp",
	} {
		parents := ReversedParents(host)
		if got, want := ds.MatchDomainReversed(parents), hs.MatchDomainReversed(parents); got != want {
			t.Errorf("domain %q: disk=%v heap=%v", host, got, want)
		}
	}
	for _, ipStr := range []string{
		"1.2.3.4",            // v4 direct hit
		"::ffff:1.2.3.4",     // 4-in-6 form of the same address — must hit v4 section
		"2001:db8::1",        // v6 hit
		"::ffff:9.9.9.9",     // 4-in-6 miss
	} {
		addr := netip.MustParseAddr(ipStr)
		if got, want := ds.MatchIP(addr), hs.MatchIP(addr); got != want {
			t.Errorf("ip %q: disk=%v heap=%v", ipStr, got, want)
		}
	}
}

func TestOpen_BadMagic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.krs")
	if err := os.WriteFile(p, []byte("NOPExxxx"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil {
		t.Fatal("expected error on bad magic")
	}
}
