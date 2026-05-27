package krs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
)

const (
	indexEntrySize = 10
)

// Section TypeID enum. New TypeIDs must be append-only — existing values
// are part of the wire contract and must not change.
const (
	typeSetTable           uint16 = 0x0001
	typeIPv4RangesBySet    uint16 = 0x0010
	typeIPv6RangesBySet    uint16 = 0x0011
	typeDomainSuffixBySet  uint16 = 0x0012
	typeDomainExcludeBySet uint16 = 0x0013
)

// WriteBundle serializes b to w in .krs format.
//
// Layout: header (8 bytes) | section index (count × 10 bytes) | payloads.
// Sections are emitted in TypeID ascending order so writer output is
// deterministic for a given input (round-trip and byte-exact tests rely
// on this; readers may not assume it).
func WriteBundle(w io.Writer, b *Bundle) error {
	ver := b.Version
	if ver == 0 {
		ver = Version
	}

	sections := collectSections(b)
	if len(sections) > 0xFFFF {
		return fmt.Errorf("krs: too many sections (%d > 65535)", len(sections))
	}

	hdr := make([]byte, headerSize)
	copy(hdr[0:4], Magic)
	binary.LittleEndian.PutUint16(hdr[4:6], ver)
	binary.LittleEndian.PutUint16(hdr[6:8], uint16(len(sections)))

	indexBytes := make([]byte, indexEntrySize*len(sections))
	payloadStart := uint32(headerSize + indexEntrySize*len(sections))
	off := payloadStart
	for i, s := range sections {
		entry := indexBytes[i*indexEntrySize:]
		binary.LittleEndian.PutUint16(entry[0:2], s.typeID)
		binary.LittleEndian.PutUint32(entry[2:6], off)
		binary.LittleEndian.PutUint32(entry[6:10], uint32(len(s.payload)))
		off += uint32(len(s.payload))
	}

	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("krs: write header: %w", err)
	}
	if _, err := w.Write(indexBytes); err != nil {
		return fmt.Errorf("krs: write index: %w", err)
	}
	for _, s := range sections {
		if _, err := w.Write(s.payload); err != nil {
			return fmt.Errorf("krs: write section 0x%04x: %w", s.typeID, err)
		}
	}
	return nil
}

// section is a compiled section ready for emission.
type section struct {
	typeID  uint16
	payload []byte
}

// collectSections builds the (sorted) section list for a bundle.
// Order: TypeID ascending.
//
// Empty payloads are skipped — a bundle with named sets but no domain
// data emits only the SetTable, not an empty DomainSuffixBySet section.
func collectSections(b *Bundle) []section {
	var out []section
	if len(b.Sets) > 0 {
		out = append(out, section{typeSetTable, encodeSetTable(b.Sets)})
	}
	if p := encodeIPRangesBySet(b.Sets, 4); len(p) > 0 {
		out = append(out, section{typeIPv4RangesBySet, p})
	}
	if p := encodeIPRangesBySet(b.Sets, 16); len(p) > 0 {
		out = append(out, section{typeIPv6RangesBySet, p})
	}
	if p := encodeDomainBySet(b.Sets, false); len(p) > 0 {
		out = append(out, section{typeDomainSuffixBySet, p})
	}
	if p := encodeDomainBySet(b.Sets, true); len(p) > 0 {
		out = append(out, section{typeDomainExcludeBySet, p})
	}
	out = append(out, collectAppSections(b.Apps)...)
	return out
}

// encodeDomainBySet serializes domains from all sets into one payload.
//
// Entries: [u16 set_idx][uvarint(len)][reversed-lower utf-8] repeated.
// Sort: (set_idx ASC, value ASC). Per-set dedup. Empty/whitespace skipped.
// No count prefix — reader scans to section Length.
//
// exclude=true reads from NamedSet.ExcludeDomains instead of DomainSuffixes.
func encodeDomainBySet(sets []NamedSet, exclude bool) []byte {
	type entry struct {
		setIdx uint16
		value  string // reversed-lower
	}
	var entries []entry
	for i, s := range sets {
		src := s.DomainSuffixes
		if exclude {
			src = s.ExcludeDomains
		}
		seen := make(map[string]struct{}, len(src))
		for _, d := range src {
			// IDNA normalize: IDN → punycode, ASCII case-fold, strip
			// trailing dot. Drops entries that aren't valid hostnames
			// (underscores, wildcards, malformed labels) so reverseASCII
			// only ever sees ASCII LDH bytes — multi-byte UTF-8 reversed
			// bytewise is non-roundtrippable against real runtime queries.
			ascii, ok := toASCIIDomain(d)
			if !ok {
				if strings.TrimSpace(d) != "" {
					slog.Warn("krs: dropping non-IDNA-normalizable domain entry",
						"set", s.Name, "entry", d)
				}
				continue
			}
			r := reverseASCII(ascii)
			if _, dup := seen[r]; dup {
				continue
			}
			seen[r] = struct{}{}
			entries = append(entries, entry{uint16(i), r})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].setIdx != entries[j].setIdx {
			return entries[i].setIdx < entries[j].setIdx
		}
		return entries[i].value < entries[j].value
	})

	var buf bytes.Buffer
	var idxb [2]byte
	var vb [binary.MaxVarintLen64]byte
	for _, e := range entries {
		binary.LittleEndian.PutUint16(idxb[:], e.setIdx)
		buf.Write(idxb[:])
		n := binary.PutUvarint(vb[:], uint64(len(e.value)))
		buf.Write(vb[:n])
		buf.WriteString(e.value)
	}
	return buf.Bytes()
}

// reverseASCII reverses a byte string. Safe for domain names (LDH-only after
// punycoding). NOT safe for arbitrary UTF-8 — would split multi-byte runes.
func reverseASCII(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// encodeSetTable: u16 count + [uvarint(len) + utf-8 name] × count.
func encodeSetTable(sets []NamedSet) []byte {
	var buf bytes.Buffer
	var hdr [2]byte
	binary.LittleEndian.PutUint16(hdr[:], uint16(len(sets)))
	buf.Write(hdr[:])
	var varintBuf [binary.MaxVarintLen64]byte
	for _, s := range sets {
		n := binary.PutUvarint(varintBuf[:], uint64(len(s.Name)))
		buf.Write(varintBuf[:n])
		buf.WriteString(s.Name)
	}
	return buf.Bytes()
}
