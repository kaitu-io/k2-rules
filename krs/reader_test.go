package krs_test

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/kaitu-io/k2-rules/krs"
)

// ReadBundle on the wire output of an empty Bundle should reconstruct
// version=1, no sets, no apps.
func TestReadBundle_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, &krs.Bundle{}); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	got, err := krs.ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version: got %d want 1", got.Version)
	}
	if len(got.Sets) != 0 {
		t.Errorf("Sets: got %d entries, want 0", len(got.Sets))
	}
	if got.Apps != nil {
		t.Errorf("Apps: got %+v, want nil", got.Apps)
	}
}

func TestReadBundle_TooShort(t *testing.T) {
	for _, n := range []int{0, 1, 7} {
		data := make([]byte, n)
		if _, err := krs.ReadBundle(data); err == nil {
			t.Errorf("ReadBundle(%d bytes): expected error, got nil", n)
		}
	}
}

func TestReadBundle_BadMagic(t *testing.T) {
	data := []byte{'X', 'X', 'X', 'X', 1, 0, 0, 0}
	if _, err := krs.ReadBundle(data); err == nil {
		t.Errorf("ReadBundle bad magic: expected error, got nil")
	}
}

// Round-trip: NamedSet names survive write→read with original order preserved.
func TestReadBundle_RecoversSetNames(t *testing.T) {
	in := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "google"},
		{Name: "youtube"},
		{Name: "telegram"},
	}}
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, in); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	out, err := krs.ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	if len(out.Sets) != 3 {
		t.Fatalf("Sets: got %d want 3", len(out.Sets))
	}
	for i, want := range []string{"google", "youtube", "telegram"} {
		if out.Sets[i].Name != want {
			t.Errorf("Sets[%d].Name: got %q want %q", i, out.Sets[i].Name, want)
		}
	}
}

// Higher version than the reader knows is informational, not an error.
// Forward-compat lives in TypeID enum extension, not the version field.
func TestReadBundle_HigherVersionAccepted(t *testing.T) {
	data := []byte{'K', '2', 'R', 'L', 99, 0, 0, 0}
	got, err := krs.ReadBundle(data)
	if err != nil {
		t.Fatalf("ReadBundle higher version: %v", err)
	}
	if got.Version != 99 {
		t.Errorf("Version: got %d want 99", got.Version)
	}
}

// Section payload order in the file must NOT matter — the index entries
// (TypeID, offset, length) are authoritative. CLAUDE.md/format.go state
// this contract explicitly; this test locks it.
//
// Build a canonical bundle, then re-emit the same sections in REVERSE
// payload order (re-writing the index so offsets point to the new
// positions). Both files must produce semantically equivalent Bundles.
func TestReadBundle_SectionOrderIndependent(t *testing.T) {
	canonical := buildMultiSectionBundle(t)

	// Parse canonical layout: header (8) + index (count*10) + sections.
	sectionCount := int(canonical[6]) | int(canonical[7])<<8
	indexStart := 8
	indexEnd := indexStart + sectionCount*10

	type sec struct {
		typeID  uint16
		payload []byte
	}
	sections := make([]sec, sectionCount)
	for i := range sectionCount {
		e := canonical[indexStart+i*10:]
		typeID := uint16(e[0]) | uint16(e[1])<<8
		off := uint32(e[2]) | uint32(e[3])<<8 | uint32(e[4])<<16 | uint32(e[5])<<24
		length := uint32(e[6]) | uint32(e[7])<<8 | uint32(e[8])<<16 | uint32(e[9])<<24
		sections[i] = sec{typeID, append([]byte(nil), canonical[off:off+length]...)}
	}

	// Rebuild with sections in REVERSE payload order (TypeID index entries
	// also reversed so we test both reversal axes).
	reversed := make([]byte, indexEnd)
	copy(reversed, canonical[:indexEnd])
	// Re-walk and write payloads in reverse, updating offsets.
	payloadOff := uint32(indexEnd)
	for i := range sectionCount {
		src := sections[sectionCount-1-i] // reverse pick
		e := reversed[indexStart+i*10:]
		e[0] = byte(src.typeID)
		e[1] = byte(src.typeID >> 8)
		e[2] = byte(payloadOff)
		e[3] = byte(payloadOff >> 8)
		e[4] = byte(payloadOff >> 16)
		e[5] = byte(payloadOff >> 24)
		l := uint32(len(src.payload))
		e[6] = byte(l)
		e[7] = byte(l >> 8)
		e[8] = byte(l >> 16)
		e[9] = byte(l >> 24)
		reversed = append(reversed, src.payload...)
		payloadOff += l
	}

	bCanon, err := krs.ReadBundle(canonical)
	if err != nil {
		t.Fatalf("ReadBundle(canonical): %v", err)
	}
	bRev, err := krs.ReadBundle(reversed)
	if err != nil {
		t.Fatalf("ReadBundle(reversed): %v", err)
	}

	if len(bCanon.Sets) != len(bRev.Sets) {
		t.Fatalf("set count: canonical=%d reversed=%d", len(bCanon.Sets), len(bRev.Sets))
	}
	// Behavioral equivalence: same Match results for a sweep of probes.
	probes := []string{
		"google.com", "mail.google.com", "fakegoogle.com",
		"qq.com", "mp.weixin.qq.com", "y.qq.com",
		"unrelated.example",
	}
	for i := range bCanon.Sets {
		if bCanon.Sets[i].Name != bRev.Sets[i].Name {
			t.Errorf("set[%d] name: canonical=%q reversed=%q",
				i, bCanon.Sets[i].Name, bRev.Sets[i].Name)
		}
		for _, h := range probes {
			a := bCanon.Sets[i].MatchDomain(h)
			b := bRev.Sets[i].MatchDomain(h)
			if a != b {
				t.Errorf("set[%d] %q MatchDomain(%q): canonical=%v reversed=%v",
					i, bCanon.Sets[i].Name, h, a, b)
			}
		}
	}
}

// buildMultiSectionBundle returns canonical .krs bytes for a bundle that
// exercises every TypeID currently emitted, so section-order tests have
// real variety to permute.
func buildMultiSectionBundle(t *testing.T) []byte {
	t.Helper()
	b := &krs.Bundle{
		Sets: []krs.NamedSet{
			{
				Name:           "google",
				DomainSuffixes: []string{"google.com", "youtube.com"},
				ExcludeDomains: []string{"localized.google.com"},
				CIDRs:          []string{"8.8.8.0/24", "2001:db8::/32"},
			},
			{
				Name:           "cn-sites",
				DomainSuffixes: []string{"qq.com", "weixin.qq.com"},
			},
		},
		Apps: &krs.AppPatterns{
			Android: krs.AndroidPatterns{
				Apps:       []string{"com.tencent.*"},
				Installers: []string{"com.android.vending"},
			},
			Windows: krs.WindowsPatterns{Apps: []string{"wechat*"}},
			Darwin:  krs.DarwinPatterns{Apps: []string{"WeChat*"}},
		},
	}
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	return buf.Bytes()
}

// Adversarial input: a hand-crafted bundle whose length-prefix uvarint
// decodes to a value > math.MaxInt64. Converting that to int wraps to
// a large negative number, which bypasses naive `pos+int(strLen) > len(payload)`
// bounds checks and reaches `payload[pos : pos+int(strLen)]` with end < start
// — causing a runtime panic in current code.
//
// Reader contract: untrusted CDN/MITM bytes must produce a clean error,
// never a panic. (Loader does NOT recover panics; a single bad bundle
// would otherwise crash the entire k2 client.)
func TestReadBundle_HostileUvarintLength(t *testing.T) {
	maliciousUvarint := func() []byte {
		// binary.PutUvarint for 1<<63 produces 10 bytes ending in 0x01.
		var buf [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(buf[:], 1<<63)
		return buf[:n]
	}()

	runHostile := func(t *testing.T, name string, data []byte) {
		t.Helper()
		var (
			err      error
			panicVal any
		)
		func() {
			defer func() {
				panicVal = recover()
			}()
			_, err = krs.ReadBundle(data)
		}()
		if panicVal != nil {
			t.Errorf("%s: ReadBundle panicked: %v (want clean error)", name, panicVal)
			return
		}
		if err == nil {
			t.Errorf("%s: ReadBundle returned nil error (want error on hostile input)", name)
		}
	}

	t.Run("DomainSection", func(t *testing.T) {
		// Layout:
		//   header(8) | SetTable idx(10) | Domain idx(10) | SetTable | Domain
		//   SetTable payload: count=1, uvarint(6), "victim"           = 9 bytes
		//   Domain   payload: set_idx=0(2) + maliciousUvarint(10) + 0x00 = 13 bytes
		setTablePL := []byte{0x01, 0x00, 6, 'v', 'i', 'c', 't', 'i', 'm'}
		domainPL := append([]byte{0x00, 0x00}, maliciousUvarint...)
		domainPL = append(domainPL, 0x00)
		data := buildBundleWithSections(t, []sectionSpec{
			{typeID: 0x0001, payload: setTablePL},
			{typeID: 0x0012, payload: domainPL},
		})
		runHostile(t, "DomainSection", data)
	})

	t.Run("ExcludeSection", func(t *testing.T) {
		setTablePL := []byte{0x01, 0x00, 6, 'v', 'i', 'c', 't', 'i', 'm'}
		excludePL := append([]byte{0x00, 0x00}, maliciousUvarint...)
		excludePL = append(excludePL, 0x00)
		data := buildBundleWithSections(t, []sectionSpec{
			{typeID: 0x0001, payload: setTablePL},
			{typeID: 0x0013, payload: excludePL},
		})
		runHostile(t, "ExcludeSection", data)
	})

	t.Run("SetTable", func(t *testing.T) {
		// SetTable payload: count=1, then malicious uvarint for the name length.
		setTablePL := append([]byte{0x01, 0x00}, maliciousUvarint...)
		setTablePL = append(setTablePL, 0x00) // garbage tail
		data := buildBundleWithSections(t, []sectionSpec{
			{typeID: 0x0001, payload: setTablePL},
		})
		runHostile(t, "SetTable", data)
	})

	t.Run("AppSection", func(t *testing.T) {
		// Flat list section, no SetTable dependency.
		appsPL := append([]byte{}, maliciousUvarint...)
		appsPL = append(appsPL, 0x00)
		data := buildBundleWithSections(t, []sectionSpec{
			{typeID: 0x0101, payload: appsPL}, // AndroidApps
		})
		runHostile(t, "AppSection", data)
	})
}

// Adversarial input: a CDN-controlled bundle whose domain section entries
// are deliberately UNSORTED. The writer always produces sorted output,
// but the reader trusts the wire and passes the slice straight to
// sort.SearchStrings — which on unsorted data can binary-search past a
// legitimate rule, hiding it from MatchDomain.
//
// Concrete exploit shape: place the target rule at the right of an array
// of strings that all sort GREATER than the target. The search keeps
// halving left, never visits the right partition, and reports "not found"
// even though the rule is in the table.
//
// Reader contract: matching outcomes must be independent of in-bundle
// ordering (Defense in Depth — the writer is the canonical sorter, the
// reader is the safety net).
func TestReadBundle_HostileUnsortedDomain(t *testing.T) {
	// All five reversed-domain forms are > "moc.elgoog" lexicographically,
	// chosen so binary search for "moc.elgoog" halves left and never
	// visits index 4.
	// Each entry: u16 set_idx + uvarint(len) + bytes.
	encodeEntry := func(setIdx uint16, reversed string) []byte {
		var b []byte
		b = append(b, byte(setIdx), byte(setIdx>>8))
		var lb [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(lb[:], uint64(len(reversed)))
		b = append(b, lb[:n]...)
		b = append(b, []byte(reversed)...)
		return b
	}
	domainPL := bytes.Join([][]byte{
		encodeEntry(0, "moc.elppa"),     // > moc.elgoog (p > g at pos 5)
		encodeEntry(0, "moc.koobecaf"),  // > moc.elgoog (k > e at pos 4)
		encodeEntry(0, "moc.tfosorcim"), // > moc.elgoog (t > e at pos 4)
		encodeEntry(0, "moc.oohay"),     // > moc.elgoog (o > e at pos 4)
		encodeEntry(0, "moc.elgoog"),    // THE rule that must still match
	}, nil)

	setTablePL := []byte{0x01, 0x00, 6, 'v', 'i', 'c', 't', 'i', 'm'}
	data := buildBundleWithSections(t, []sectionSpec{
		{typeID: 0x0001, payload: setTablePL},
		{typeID: 0x0012, payload: domainPL},
	})

	got, err := krs.ReadBundle(data)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	set := &got.Sets[0]
	// google.com (parent) and any sub must match.
	hits := []string{"google.com", "www.google.com", "deeper.sub.google.com"}
	for _, h := range hits {
		if !set.MatchDomain(h) {
			t.Errorf("MatchDomain(%q) = false — unsorted-bundle exploit succeeded "+
				"(rule present but binary search skipped it)", h)
		}
	}
	// Negative control: non-rule hosts still miss.
	if set.MatchDomain("example.org") {
		t.Error("MatchDomain(example.org) = true, want false")
	}
}

// Adversarial input: IPv4 ranges in deliberately wrong order. ipRangeSection.
// Contains uses sort.Search assuming starts are sorted ascending; on unsorted
// input the binary search can skip a covering range, hiding it from MatchIP.
//
// Exploit shape: place ranges whose starts all sort GREATER than the target
// address ahead of the actual covering range. Search halves left and never
// visits the covering entry.
func TestReadBundle_HostileUnsortedIPRanges(t *testing.T) {
	// Entry layout: u16 set_idx + 4B start + 4B end.
	entry := func(setIdx uint16, startA, startB, startC, startD byte, endA, endB, endC, endD byte) []byte {
		return []byte{
			byte(setIdx), byte(setIdx >> 8),
			startA, startB, startC, startD,
			endA, endB, endC, endD,
		}
	}
	// All decoy starts > 8.8.8.8. Covering range [8.8.8.0–8.8.8.255] is last,
	// at an index sort.Search will not visit when halving left for 8.8.8.8.
	ipPL := bytes.Join([][]byte{
		entry(0, 9, 0, 0, 0, 9, 255, 255, 255),
		entry(0, 10, 0, 0, 0, 10, 255, 255, 255),
		entry(0, 100, 0, 0, 0, 100, 255, 255, 255),
		entry(0, 200, 0, 0, 0, 200, 255, 255, 255),
		entry(0, 8, 8, 8, 0, 8, 8, 8, 255), // the rule that must still match
	}, nil)

	setTablePL := []byte{0x01, 0x00, 6, 'v', 'i', 'c', 't', 'i', 'm'}
	data := buildBundleWithSections(t, []sectionSpec{
		{typeID: 0x0001, payload: setTablePL},
		{typeID: 0x0010, payload: ipPL}, // IPv4RangesBySet
	})

	got, err := krs.ReadBundle(data)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	set := &got.Sets[0]

	hits := []string{"8.8.8.0", "8.8.8.128", "8.8.8.255"}
	for _, h := range hits {
		if !set.MatchIP(netip.MustParseAddr(h)) {
			t.Errorf("MatchIP(%s) = false — unsorted-bundle exploit succeeded "+
				"(range present but binary search skipped it)", h)
		}
	}
	if set.MatchIP(netip.MustParseAddr("7.0.0.0")) {
		t.Error("MatchIP(7.0.0.0) = true, want false (out of range)")
	}
}

// Fuzz harness: ReadBundle must NEVER panic on untrusted input. Catches
// future regressions in any decoder path. Seed corpus covers the known
// adversarial shapes (malicious uvarint, unsorted entries, truncated
// payloads); the fuzzer extends from there. Without -fuzz this runs as a
// regular subtest over the seed corpus.
func FuzzReadBundle(f *testing.F) {
	// Empty / shortest possible.
	f.Add([]byte{})
	f.Add([]byte("K2RL"))
	f.Add([]byte{'K', '2', 'R', 'L', 1, 0, 0, 0})
	// Malicious uvarint shapes.
	var maliciousUvarint [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(maliciousUvarint[:], 1<<63)
	stab := append([]byte{}, maliciousUvarint[:n]...)
	f.Add(buildBundleForFuzz([]sectionSpec{
		{typeID: 0x0001, payload: append([]byte{0x01, 0x00}, append(stab, 0x00)...)},
	}))
	// Unsorted domain section.
	encodeEntry := func(setIdx uint16, reversed string) []byte {
		var b []byte
		b = append(b, byte(setIdx), byte(setIdx>>8))
		var lb [binary.MaxVarintLen64]byte
		ln := binary.PutUvarint(lb[:], uint64(len(reversed)))
		b = append(b, lb[:ln]...)
		b = append(b, []byte(reversed)...)
		return b
	}
	f.Add(buildBundleForFuzz([]sectionSpec{
		{typeID: 0x0001, payload: []byte{0x01, 0x00, 4, 'a', 'b', 'c', 'd'}},
		{typeID: 0x0012, payload: bytes.Join([][]byte{
			encodeEntry(0, "moc.zzz"),
			encodeEntry(0, "moc.aaa"),
		}, nil)},
	}))
	// Section index that overlaps header bytes (offset=0).
	f.Add([]byte{
		'K', '2', 'R', 'L', 0x01, 0x00, 0x01, 0x00,
		0x01, 0x00, // TypeID=0x0001 (SetTable)
		0, 0, 0, 0, // offset=0 (overlaps header)
		8, 0, 0, 0, // length=8
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ReadBundle panicked on input (%d bytes, sha-leading-16=%x): %v",
					len(data), firstN(data, 16), r)
			}
		}()
		b, err := krs.ReadBundle(data)
		if err != nil || b == nil {
			return
		}
		// If parse succeeded, Match* must also be panic-free on arbitrary queries.
		for _, h := range []string{"a", "a.b", "google.com", "", "."} {
			for i := range b.Sets {
				_ = b.Sets[i].MatchDomain(h)
			}
		}
		for _, ip := range []string{"8.8.8.8", "1.2.3.4", "2001:db8::1"} {
			addr, _ := netip.ParseAddr(ip)
			for i := range b.Sets {
				_ = b.Sets[i].MatchIP(addr)
			}
		}
	})
}

func firstN(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// buildBundleForFuzz mirrors buildBundleWithSections but tolerates the
// test-helper t parameter being unavailable inside fuzz seed setup.
func buildBundleForFuzz(secs []sectionSpec) []byte {
	const hdr = 8
	idxBytes := 10 * len(secs)
	payloadOff := hdr + idxBytes
	out := make([]byte, 0, payloadOff+1024)
	out = append(out, 'K', '2', 'R', 'L', 0x01, 0x00)
	out = append(out, byte(len(secs)), byte(len(secs)>>8))
	off := uint32(payloadOff)
	for _, s := range secs {
		out = append(out, byte(s.typeID), byte(s.typeID>>8))
		out = append(out, byte(off), byte(off>>8), byte(off>>16), byte(off>>24))
		l := uint32(len(s.payload))
		out = append(out, byte(l), byte(l>>8), byte(l>>16), byte(l>>24))
		off += l
	}
	for _, s := range secs {
		out = append(out, s.payload...)
	}
	return out
}

type sectionSpec struct {
	typeID  uint16
	payload []byte
}

// buildBundleWithSections assembles a minimal .krs file with the given
// sections in order, using a fresh offset table — adversarial tests use it
// to plant malformed payloads without writing through the normal writer.
func buildBundleWithSections(t *testing.T, secs []sectionSpec) []byte {
	t.Helper()
	const hdr = 8
	idxBytes := 10 * len(secs)
	payloadOff := hdr + idxBytes

	out := make([]byte, 0, payloadOff+1024)
	// Header: magic, version=1, sectionCount.
	out = append(out, 'K', '2', 'R', 'L', 0x01, 0x00)
	out = append(out,
		byte(len(secs)), byte(len(secs)>>8),
	)
	// Index entries.
	off := uint32(payloadOff)
	for _, s := range secs {
		out = append(out, byte(s.typeID), byte(s.typeID>>8))
		out = append(out,
			byte(off), byte(off>>8), byte(off>>16), byte(off>>24),
		)
		l := uint32(len(s.payload))
		out = append(out, byte(l), byte(l>>8), byte(l>>16), byte(l>>24))
		off += l
	}
	// Payloads.
	for _, s := range secs {
		out = append(out, s.payload...)
	}
	return out
}

// Forward-compat: a bundle containing an unknown TypeID alongside a known
// one is still decoded successfully. The known section is parsed, the
// unknown one is skipped (logged) — no error returned, no data corruption.
func TestReadBundle_UnknownTypeIDSkipped(t *testing.T) {
	// Hand-craft a bundle with two sections:
	//   [TypeID=0x0001 SetTable: {"google"}]   — known
	//   [TypeID=0x7FFF: 4 arbitrary bytes]     — unknown
	setTablePayload := []byte{0x01, 0x00, 6, 'g', 'o', 'o', 'g', 'l', 'e'}
	unknownPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	indexBase := 8 // after header
	payloadBase := indexBase + 2*10

	data := []byte{
		'K', '2', 'R', 'L', 0x01, 0x00, 0x02, 0x00, // header
	}
	// index entry 0: SetTable
	data = append(data,
		0x01, 0x00,
		byte(payloadBase), 0, 0, 0,
		byte(len(setTablePayload)), 0, 0, 0,
	)
	// index entry 1: TypeID 0x7FFF
	unknownOffset := payloadBase + len(setTablePayload)
	data = append(data,
		0xFF, 0x7F,
		byte(unknownOffset), 0, 0, 0,
		byte(len(unknownPayload)), 0, 0, 0,
	)
	data = append(data, setTablePayload...)
	data = append(data, unknownPayload...)

	got, err := krs.ReadBundle(data)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	if len(got.Sets) != 1 || got.Sets[0].Name != "google" {
		t.Errorf("expected set 'google', got %+v", got.Sets)
	}
}
