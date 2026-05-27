package krs

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
)

// ipRangeSection holds sorted [start, end] byte ranges for one set.
// 4 or 16 bytes per address, network byte order.
//
// Ranges are pre-merged on write so the slice is in canonical form:
// non-overlapping, non-adjacent, sorted by start.
type ipRangeSection struct {
	addrLen int      // 4 (v4) or 16 (v6)
	starts  [][]byte // len == count, each addrLen bytes
	ends    [][]byte // len == count
}

// canonicalize sorts and merges this section's ranges. Used by the reader
// as defense in depth: writer output is already canonical, but a hostile
// or buggy producer could ship unsorted or overlapping ranges that bypass
// the binary search in Contains. Idempotent — no-op when input is already
// canonical (the common case after a canonical writer).
func (s *ipRangeSection) canonicalize() {
	if len(s.starts) <= 1 {
		return
	}
	// Already sorted by start? Fast path skips re-merge for canonical input.
	sorted := true
	for i := 1; i < len(s.starts); i++ {
		if bytes.Compare(s.starts[i-1], s.starts[i]) > 0 {
			sorted = false
			break
		}
	}
	pairs := make([]rangePair, len(s.starts))
	for i := range s.starts {
		pairs[i] = rangePair{start: s.starts[i], end: s.ends[i]}
	}
	if !sorted {
		sort.Slice(pairs, func(i, j int) bool {
			return bytes.Compare(pairs[i].start, pairs[j].start) < 0
		})
	}
	merged := mergeRanges(pairs, s.addrLen)
	if len(merged) == len(s.starts) && sorted {
		return // canonical already; preserve original slices
	}
	s.starts = s.starts[:0]
	s.ends = s.ends[:0]
	for _, p := range merged {
		s.starts = append(s.starts, p.start)
		s.ends = append(s.ends, p.end)
	}
}

// Contains reports whether addr is within any range in this section.
func (s *ipRangeSection) Contains(raw []byte) bool {
	if len(s.starts) == 0 || len(raw) != s.addrLen {
		return false
	}
	// Largest start ≤ raw via binary search.
	idx := sort.Search(len(s.starts), func(i int) bool {
		return bytes.Compare(s.starts[i], raw) > 0
	})
	if idx == 0 {
		return false
	}
	cand := idx - 1
	return bytes.Compare(s.ends[cand], raw) >= 0
}

// MatchIP reports whether addr falls within any CIDR rule in this set.
func (s *NamedSet) MatchIP(addr netip.Addr) bool {
	if addr.Is4() {
		b := addr.As4()
		return s.ipv4.Contains(b[:])
	}
	if addr.Is6() {
		b := addr.As16()
		// Handle 4-in-6 addresses by also checking v4 section.
		if addr.Is4In6() {
			b4 := addr.Unmap().As4()
			if s.ipv4.Contains(b4[:]) {
				return true
			}
		}
		return s.ipv6.Contains(b[:])
	}
	return false
}

// rangePair is the writer's intermediate range form.
type rangePair struct {
	start []byte // addrLen bytes, network order
	end   []byte
}

// parseCIDRsByFamily expands CIDR strings into v4 / v6 [start, end] pairs.
// Unparseable or wrong-family entries are silently dropped (writer trusts
// upstream validation; CIDR validation is the validator's job).
func parseCIDRsByFamily(cidrs []string) (v4, v6 []rangePair) {
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		p = p.Masked()
		bits := p.Bits()
		addr := p.Addr()
		if addr.Is4() {
			start := addr.As4()
			end := start
			fillHostBits(end[:], bits)
			v4 = append(v4, rangePair{start: start[:], end: end[:]})
		} else if addr.Is6() {
			start := addr.As16()
			end := start
			fillHostBits(end[:], bits)
			v6 = append(v6, rangePair{start: start[:], end: end[:]})
		}
	}
	return v4, v6
}

// fillHostBits ORs the host portion of an address (bits below prefixBits)
// with all-ones, producing the inclusive end of the CIDR range. Operates
// on either 4 or 16 byte addresses.
func fillHostBits(b []byte, prefixBits int) {
	for i := range b {
		bitOffset := i * 8
		switch {
		case bitOffset >= prefixBits:
			b[i] |= 0xFF
		case prefixBits-bitOffset < 8:
			b[i] |= byte(0xFF >> (prefixBits - bitOffset))
		}
	}
}

// mergeRanges sorts by start then folds overlapping/adjacent ranges
// into single entries. Input is mutated.
func mergeRanges(rs []rangePair, addrLen int) []rangePair {
	if len(rs) <= 1 {
		return rs
	}
	sort.Slice(rs, func(i, j int) bool {
		return bytes.Compare(rs[i].start, rs[j].start) < 0
	})
	merged := []rangePair{rs[0]}
	for i := 1; i < len(rs); i++ { //nolint:intrange // start at 1
		last := &merged[len(merged)-1]
		nextAfterLast := incBytes(last.end, addrLen)
		// If rs[i].start ≤ last.end + 1, merge.
		if nextAfterLast != nil && bytes.Compare(rs[i].start, nextAfterLast) <= 0 {
			if bytes.Compare(rs[i].end, last.end) > 0 {
				last.end = rs[i].end
			}
			continue
		}
		merged = append(merged, rs[i])
	}
	return merged
}

// incBytes returns b+1 as a new addrLen-byte slice, or nil on overflow.
func incBytes(b []byte, addrLen int) []byte {
	out := make([]byte, addrLen)
	copy(out, b)
	carry := byte(1)
	for i := addrLen - 1; i >= 0 && carry > 0; i-- {
		sum := uint16(out[i]) + uint16(carry)
		out[i] = byte(sum)
		carry = byte(sum >> 8)
	}
	if carry > 0 {
		return nil // overflow: b was already max address
	}
	return out
}

// decodeIPRangesBySet reads (u16 set_idx, start, end) entries from payload
// until exhausted. Entries are assumed pre-sorted by (set_idx, start) and
// pre-merged per set — reader appends each set's entries in arrival order.
func decodeIPRangesBySet(b *Bundle, payload []byte, addrLen int) error {
	entrySize := 2 + 2*addrLen
	if len(payload)%entrySize != 0 {
		return fmt.Errorf("ipv%d section: payload length %d not a multiple of %d",
			ipFamily(addrLen), len(payload), entrySize)
	}
	for off := 0; off < len(payload); off += entrySize { //nolint:intrange // step != 1
		setIdx := uint16(payload[off]) | uint16(payload[off+1])<<8
		start := append([]byte(nil), payload[off+2:off+2+addrLen]...)
		end := append([]byte(nil), payload[off+2+addrLen:off+entrySize]...)
		if int(setIdx) >= len(b.Sets) {
			return fmt.Errorf("ipv%d section: set_idx=%d out of range (have %d sets)",
				ipFamily(addrLen), setIdx, len(b.Sets))
		}
		target := &b.Sets[setIdx].ipv4
		if addrLen == 16 {
			target = &b.Sets[setIdx].ipv6
		}
		target.addrLen = addrLen
		target.starts = append(target.starts, start)
		target.ends = append(target.ends, end)
	}
	return nil
}

func ipFamily(addrLen int) int {
	if addrLen == 4 {
		return 4
	}
	return 6
}

// encodeIPRangesBySet emits (u16 set_idx, start, end) entries.
// Each set's ranges are pre-merged. Sort: (set_idx ASC, start ASC bytewise).
func encodeIPRangesBySet(sets []NamedSet, addrLen int) []byte {
	type entry struct {
		setIdx uint16
		start  []byte
		end    []byte
	}
	var entries []entry
	for i, s := range sets {
		v4, v6 := parseCIDRsByFamily(s.CIDRs)
		var pool []rangePair
		if addrLen == 4 {
			pool = mergeRanges(v4, 4)
		} else {
			pool = mergeRanges(v6, 16)
		}
		for _, p := range pool {
			entries = append(entries, entry{uint16(i), p.start, p.end})
		}
	}
	if len(entries) == 0 {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].setIdx != entries[j].setIdx {
			return entries[i].setIdx < entries[j].setIdx
		}
		return bytes.Compare(entries[i].start, entries[j].start) < 0
	})

	var buf bytes.Buffer
	var idxb [2]byte
	for _, e := range entries {
		idxb[0] = byte(e.setIdx)
		idxb[1] = byte(e.setIdx >> 8)
		buf.Write(idxb[:])
		buf.Write(e.start)
		buf.Write(e.end)
	}
	return buf.Bytes()
}
