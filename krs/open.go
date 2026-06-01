package krs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// DiskBundle is a read-only, mmap-backed bundle. Resident dirty heap is
// O(set count): only per-set descriptors pointing into the mmap, never the
// rules themselves. Constitution: see krs/CONSTITUTION.md.
type DiskBundle struct {
	data  []byte       // the whole mmap (clean / file-backed)
	close func() error // unmap
	names []string
	sets  []diskSet
}

// diskSet holds per-set mmap sub-slices and implements Matcher
// (MatchDomainReversed, MatchIP) by searching directly on the mapped bytes.
type diskSet struct {
	name    string
	suffix  domainBlock
	exclude domainBlock
	v4      ipBlock
	v6      ipBlock
}

// domainBlock points at one set's slice of the domain offset index plus the
// shared domain payload. Both are sub-slices of the mmap.
type domainBlock struct {
	payload []byte // whole domain section payload (mmap)
	offsets []byte // this set's u32 offsets (entryCount*4 bytes, mmap)
}

// ipBlock points at one set's contiguous run of fixed-width IP entries.
type ipBlock struct {
	payload []byte // this set's entries: [u16 set_idx][start][end] × count (mmap)
	addrLen int    // 4 or 16
}

// Open maps path read-only and builds per-set descriptors. The returned bundle
// must be Closed to unmap. Errors (not silent fallback) on bad magic, truncated
// index, out-of-bounds section, or a domain payload missing its index section.
func Open(path string) (*DiskBundle, error) {
	data, closeFn, err := mmapReadOnly(path)
	if err != nil {
		return nil, err
	}
	db := &DiskBundle{data: data, close: closeFn}
	if err := db.parse(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// Close unmaps the bundle. Safe to call once.
func (db *DiskBundle) Close() error {
	if db.close != nil {
		c := db.close
		db.close = nil
		return c()
	}
	return nil
}

// SetNames returns the set names in bundle order. The caller must not modify
// the returned slice — it aliases internal state.
func (db *DiskBundle) SetNames() []string { return db.names }

func (db *DiskBundle) parse() error {
	d := db.data
	if len(d) < headerSize {
		return fmt.Errorf("krs: data too short for header (%d)", len(d))
	}
	if string(d[0:4]) != Magic {
		return fmt.Errorf("krs: bad magic %q", string(d[0:4]))
	}
	sectionCount := int(binary.LittleEndian.Uint16(d[6:8]))
	indexEnd := headerSize + indexEntrySize*sectionCount
	if len(d) < indexEnd {
		return fmt.Errorf("krs: data too short for %d-section index", sectionCount)
	}
	// Collect section payloads (bounds-checked slices into the mmap).
	secs := map[uint16][]byte{}
	for i := 0; i < sectionCount; i++ {
		e := d[headerSize+i*indexEntrySize:]
		typeID := binary.LittleEndian.Uint16(e[0:2])
		off := binary.LittleEndian.Uint32(e[2:6])
		ln := binary.LittleEndian.Uint32(e[6:10])
		if uint64(off)+uint64(ln) > uint64(len(d)) {
			return fmt.Errorf("krs: section 0x%04x out of bounds", typeID)
		}
		secs[typeID] = d[off : off+ln]
	}
	// SetTable first.
	st, ok := secs[typeSetTable]
	if !ok {
		// No sets: an empty/app-only bundle. Nothing to match on.
		return nil
	}
	names, err := decodeSetTable(st)
	if err != nil {
		return err
	}
	db.names = names
	db.sets = make([]diskSet, len(names))
	for i := range db.sets {
		db.sets[i].name = names[i]
	}
	// Domain blocks (payload requires its index; constitution: no fallback).
	if err := db.bindDomain(secs, typeDomainSuffixBySet, typeDomainSuffixIndex, false); err != nil {
		return err
	}
	if err := db.bindDomain(secs, typeDomainExcludeBySet, typeDomainExcludeIndex, true); err != nil {
		return err
	}
	// IP blocks.
	if p, ok := secs[typeIPv4RangesBySet]; ok {
		if err := db.bindIP(p, 4); err != nil {
			return err
		}
	}
	if p, ok := secs[typeIPv6RangesBySet]; ok {
		if err := db.bindIP(p, 16); err != nil {
			return err
		}
	}
	return nil
}

// bindDomain attaches each set's offset sub-slice + the shared payload.
func (db *DiskBundle) bindDomain(secs map[uint16][]byte, payID, idxID uint16, exclude bool) error {
	payload, hasPay := secs[payID]
	index, hasIdx := secs[idxID]
	if !hasPay {
		return nil // this bundle has no such domain data
	}
	if !hasIdx {
		return fmt.Errorf("krs: domain section 0x%04x present without index 0x%04x", payID, idxID)
	}
	if len(index) < 2 {
		return fmt.Errorf("krs: domain index 0x%04x too short", idxID)
	}
	setCount := int(binary.LittleEndian.Uint16(index[0:2]))
	if setCount != len(db.sets) {
		return fmt.Errorf("krs: domain index setCount=%d != %d sets", setCount, len(db.sets))
	}
	dirEnd := 2 + setCount*8
	if len(index) < dirEnd {
		return fmt.Errorf("krs: domain index directory truncated")
	}
	offTable := index[dirEnd:]
	for s := 0; s < setCount; s++ {
		start := binary.LittleEndian.Uint32(index[2+s*8:])
		count := binary.LittleEndian.Uint32(index[2+s*8+4:])
		lo := int(start) * 4
		hi := int(start+count) * 4
		if lo > hi || hi > len(offTable) {
			return fmt.Errorf("krs: domain index set %d range out of bounds", s)
		}
		blk := domainBlock{payload: payload, offsets: offTable[lo:hi]}
		if exclude {
			db.sets[s].exclude = blk
		} else {
			db.sets[s].suffix = blk
		}
	}
	return nil
}

// Sets exposes per-set matchers (pointers into db; valid until Close). Intended
// to be called once at setup — it allocates a fresh []Matcher per call, so do
// not call it on the per-lookup hot path.
func (db *DiskBundle) Sets() []Matcher {
	out := make([]Matcher, len(db.sets))
	for i := range db.sets {
		out[i] = &db.sets[i]
	}
	return out
}

var _ Matcher = (*diskSet)(nil)

// MatchDomainReversed: excludes take priority over suffixes.
func (s *diskSet) MatchDomainReversed(reversedParents []string) bool {
	if s.exclude.matchReversed(reversedParents) {
		return false
	}
	return s.suffix.matchReversed(reversedParents)
}

// matchReversed binary-searches this set's offset table for an exact hit on any
// reversed parent suffix. Allocation-free: entry values are compared as mmap
// bytes via cmpBS without materializing strings.
func (b *domainBlock) matchReversed(parents []string) bool {
	n := len(b.offsets) / 4
	if n == 0 {
		return false
	}
	for _, rq := range parents {
		lo, hi := 0, n
		for lo < hi {
			mid := (lo + hi) / 2
			if cmpBS(b.entryBytes(mid), rq) < 0 {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo < n && cmpBS(b.entryBytes(lo), rq) == 0 {
			return true
		}
	}
	return false
}

// entryBytes returns the reversed-domain value bytes of the k-th entry as a
// slice into the mmap (no allocation).
func (b *domainBlock) entryBytes(k int) []byte {
	off := binary.LittleEndian.Uint32(b.offsets[k*4:])
	p := b.payload[off+2:] // skip u16 set_idx
	l, m := binary.Uvarint(p)
	return p[m : m+int(l)]
}

// cmpBS lexicographically compares a byte slice with a string, no allocation.
// It exists alongside bytes.Compare because the query is a string and comparing
// it via bytes.Compare would require materializing a []byte (an allocation).
func cmpBS(b []byte, s string) int {
	n := len(b)
	if len(s) < n {
		n = len(s)
	}
	for i := 0; i < n; i++ {
		if b[i] != s[i] {
			if b[i] < s[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(b) < len(s):
		return -1
	case len(b) > len(s):
		return 1
	default:
		return 0
	}
}

// MatchIP mirrors NamedSet.MatchIP semantics (incl. 4-in-6) over mmap ranges.
func (s *diskSet) MatchIP(addr netip.Addr) bool {
	if addr.Is4() {
		b := addr.As4()
		return s.v4.contains(b[:])
	}
	if addr.Is6() {
		b := addr.As16()
		// Handle 4-in-6 addresses by also checking v4 section.
		if addr.Is4In6() {
			b4 := addr.Unmap().As4()
			if s.v4.contains(b4[:]) {
				return true
			}
		}
		return s.v6.contains(b[:])
	}
	return false
}

// contains binary-searches the fixed-width sorted ranges in place on the mmap.
func (blk *ipBlock) contains(raw []byte) bool {
	if blk.addrLen == 0 || len(raw) != blk.addrLen {
		return false
	}
	entrySize := 2 + 2*blk.addrLen
	n := len(blk.payload) / entrySize
	startAt := func(i int) []byte {
		o := i * entrySize
		return blk.payload[o+2 : o+2+blk.addrLen]
	}
	endAt := func(i int) []byte {
		o := i * entrySize
		return blk.payload[o+2+blk.addrLen : o+entrySize]
	}
	// Find largest start <= raw via binary search.
	lo, hi := 0, n
	for lo < hi {
		mid := (lo + hi) / 2
		if bytes.Compare(startAt(mid), raw) > 0 {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	idx := lo
	if idx == 0 {
		return false
	}
	return bytes.Compare(endAt(idx-1), raw) >= 0
}

// bindIP splits a fixed-width IP section (sorted by set_idx) into per-set
// sub-slices via two boundary binary searches per set — no full scan.
func (db *DiskBundle) bindIP(payload []byte, addrLen int) error {
	entrySize := 2 + 2*addrLen
	if len(payload)%entrySize != 0 {
		return fmt.Errorf("krs: ipv%d section not a multiple of %d", ipFamily(addrLen), entrySize)
	}
	n := len(payload) / entrySize
	setIdxAt := func(i int) int {
		return int(binary.LittleEndian.Uint16(payload[i*entrySize:]))
	}
	// lowerBound returns the first entry index whose set_idx >= target.
	lowerBound := func(target int) int {
		lo, hi := 0, n
		for lo < hi {
			mid := (lo + hi) / 2
			if setIdxAt(mid) < target {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		return lo
	}
	for s := range db.sets {
		lo := lowerBound(s)
		hi := lowerBound(s + 1)
		if lo == hi {
			continue
		}
		blk := ipBlock{payload: payload[lo*entrySize : hi*entrySize], addrLen: addrLen}
		if addrLen == 4 {
			db.sets[s].v4 = blk
		} else {
			db.sets[s].v6 = blk
		}
	}
	return nil
}
