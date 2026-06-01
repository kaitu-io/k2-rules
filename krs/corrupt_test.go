package krs

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// corruptHelpers --------------------------------------------------------------

// validDomainBytes serializes a small, valid two-set bundle with domains + IPs.
func validDomainBytes(t *testing.T) []byte {
	t.Helper()
	b := &Bundle{Sets: []NamedSet{
		{
			Name:           "cn",
			DomainSuffixes: []string{"qq.com", "weixin.qq.com", "taobao.com"},
			ExcludeDomains: []string{"intl.taobao.com"},
			CIDRs:          []string{"1.2.3.0/24", "2001:db8::/32"},
		},
		{Name: "os", DomainSuffixes: []string{"google.com"}, CIDRs: []string{"8.8.8.0/24"}},
	}}
	var buf bytes.Buffer
	if err := WriteBundle(&buf, b); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// sectionLoc finds the [off,len) and the index-entry offset of typeID.
func sectionLoc(t *testing.T, data []byte, typeID uint16) (entryAt int, off, ln uint32) {
	t.Helper()
	n := int(binary.LittleEndian.Uint16(data[6:8]))
	for i := 0; i < n; i++ {
		at := headerSize + i*indexEntrySize
		if binary.LittleEndian.Uint16(data[at:at+2]) == typeID {
			return at, binary.LittleEndian.Uint32(data[at+2 : at+6]), binary.LittleEndian.Uint32(data[at+6 : at+10])
		}
	}
	t.Fatalf("section 0x%04x not found", typeID)
	return 0, 0, 0
}

// openMatchMustNotPanic writes data, opens it, and runs domain + IP matches over
// every set. The test fails (via the normal panic→fail path) if any match panics.
// Returns whether Open accepted the bundle.
func openMatchMustNotPanic(t *testing.T, data []byte) (opened bool) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.krs")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := Open(p)
	if err != nil {
		return false
	}
	defer db.Close()
	hosts := []string{"qq.com", "weixin.qq.com", "a.weixin.qq.com", "taobao.com",
		"intl.taobao.com", "google.com", "evil.example", ""}
	ips := []string{"1.2.3.4", "8.8.8.8", "9.9.9.9", "2001:db8::1", "::ffff:1.2.3.4"}
	for _, s := range db.Sets() {
		for _, h := range hosts {
			_ = s.MatchDomainReversed(ReversedParents(h))
		}
		for _, ip := range ips {
			_ = s.MatchIP(netip.MustParseAddr(ip))
		}
	}
	return true
}

// CRITICAL: corrupt-value crash vectors — must not panic --------------------

// A corrupt offset value in the index must not panic entryBytes (payload[off+2:]).
func TestCorrupt_OffsetValue_NoPanic(t *testing.T) {
	data := validDomainBytes(t)
	_, idxOff, _ := sectionLoc(t, data, typeDomainSuffixIndex)
	setCount := int(binary.LittleEndian.Uint16(data[idxOff : idxOff+2]))
	offTableStart := int(idxOff) + 2 + setCount*8
	binary.LittleEndian.PutUint32(data[offTableStart:], 0xFFFFFFF0)
	if !openMatchMustNotPanic(t, data) {
		t.Log("Open rejected corrupt-offset bundle (also acceptable)")
	}
}

// A corrupt uvarint length in the payload must not panic entryBytes (p[m:m+l]).
func TestCorrupt_LengthPrefix_NoPanic(t *testing.T) {
	data := validDomainBytes(t)
	_, payOff, _ := sectionLoc(t, data, typeDomainSuffixBySet)
	pos := int(payOff) + 2 // skip u16 set_idx of the first entry
	// 0xFF 0xFF 0xFF 0xFF 0x0F decodes to a huge uvarint length.
	copy(data[pos:], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F})
	if !openMatchMustNotPanic(t, data) {
		t.Log("Open rejected corrupt-length bundle (also acceptable)")
	}
}

// A valid bundle still matches correctly (positive control alongside the fix).
func TestCorrupt_ValidStillMatches(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ok.krs")
	if err := os.WriteFile(p, validDomainBytes(t), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cn := db.Sets()[0]
	if !cn.MatchDomainReversed(ReversedParents("weixin.qq.com")) {
		t.Error("valid bundle: weixin.qq.com should match cn")
	}
	if cn.MatchDomainReversed(ReversedParents("intl.taobao.com")) {
		t.Error("valid bundle: intl.taobao.com is excluded, must not match")
	}
	if !cn.MatchIP(netip.MustParseAddr("1.2.3.4")) {
		t.Error("valid bundle: 1.2.3.4 should match cn")
	}
}

// fail-loud Open rejections (structural corruption) -------------------------

func TestCorrupt_TruncatedHeader(t *testing.T) {
	if openMatchMustNotPanic(t, []byte("K2RL")) {
		t.Error("Open accepted a 4-byte file")
	}
}

func TestCorrupt_TruncatedIndex(t *testing.T) {
	data := validDomainBytes(t)
	// Claim more sections than the file can hold for the index.
	binary.LittleEndian.PutUint16(data[6:8], 0xFFFF)
	if openMatchMustNotPanic(t, data) {
		t.Error("Open accepted a truncated section index")
	}
}

func TestCorrupt_SectionOutOfBounds(t *testing.T) {
	data := validDomainBytes(t)
	at, _, _ := sectionLoc(t, data, typeSetTable)
	binary.LittleEndian.PutUint32(data[at+6:at+10], 0xFFFFFFFF) // huge length
	if openMatchMustNotPanic(t, data) {
		t.Error("Open accepted an out-of-bounds section")
	}
}

func TestCorrupt_DomainPayloadWithoutIndex(t *testing.T) {
	data := validDomainBytes(t)
	at, _, _ := sectionLoc(t, data, typeDomainSuffixIndex)
	binary.LittleEndian.PutUint16(data[at:at+2], 0x9999) // hide the index TypeID
	if openMatchMustNotPanic(t, data) {
		t.Error("Open accepted a domain payload missing its index section")
	}
}

func TestCorrupt_IndexSetCountMismatch(t *testing.T) {
	data := validDomainBytes(t)
	_, idxOff, _ := sectionLoc(t, data, typeDomainSuffixIndex)
	binary.LittleEndian.PutUint16(data[idxOff:idxOff+2], 0x00FF) // wrong setCount
	if openMatchMustNotPanic(t, data) {
		t.Error("Open accepted an index whose setCount != number of sets")
	}
}

func TestCorrupt_PerSetRangeOutOfBounds(t *testing.T) {
	data := validDomainBytes(t)
	_, idxOff, _ := sectionLoc(t, data, typeDomainSuffixIndex)
	// directory entry 0 = {u32 start, u32 count}; blow up count.
	binary.LittleEndian.PutUint32(data[int(idxOff)+2+4:], 0x7FFFFFFF)
	if openMatchMustNotPanic(t, data) {
		t.Error("Open accepted a per-set offset range past the offset table")
	}
}

func TestCorrupt_IPSectionNotMultiple(t *testing.T) {
	data := validDomainBytes(t)
	at, _, ln := sectionLoc(t, data, typeIPv4RangesBySet)
	binary.LittleEndian.PutUint32(data[at+6:at+10], ln-1) // not a multiple of entrySize
	if openMatchMustNotPanic(t, data) {
		t.Error("Open accepted an IPv4 section whose length is not a multiple of the entry size")
	}
}
