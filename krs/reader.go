package krs

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"sort"
)

const headerSize = 8

// ReadBundle parses a .krs byte slice into a Bundle.
//
// Returns an error for missing/bad magic or truncated input. Unknown
// section TypeIDs are not an error — they are silently skipped (with
// a warning log) for enum-driven forward-compat.
func ReadBundle(data []byte) (*Bundle, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("krs: data too short for header (%d bytes)", len(data))
	}
	if string(data[0:4]) != Magic {
		return nil, fmt.Errorf("krs: bad magic %q", string(data[0:4]))
	}

	b := &Bundle{
		Version: binary.LittleEndian.Uint16(data[4:6]),
	}
	sectionCount := int(binary.LittleEndian.Uint16(data[6:8]))

	indexEnd := headerSize + indexEntrySize*sectionCount
	if len(data) < indexEnd {
		return nil, fmt.Errorf("krs: data too short for %d-section index", sectionCount)
	}

	// Two-pass decode so file-order is irrelevant (CLAUDE.md format
	// contract: "section index is authoritative — file order does not
	// matter"). Per-set sections (Domain/IP) depend on SetTable having
	// allocated b.Sets, so SetTable goes first regardless of position.
	for pass := range 2 {
		for i := range sectionCount {
			entry := data[headerSize+i*indexEntrySize:]
			typeID := binary.LittleEndian.Uint16(entry[0:2])
			offset := binary.LittleEndian.Uint32(entry[2:6])
			length := binary.LittleEndian.Uint32(entry[6:10])

			if uint64(offset)+uint64(length) > uint64(len(data)) {
				return nil, fmt.Errorf("krs: section[%d] type=0x%04x payload out of bounds (off=%d len=%d data=%d)",
					i, typeID, offset, length, len(data))
			}
			payload := data[offset : offset+length]

			isSetTable := typeID == typeSetTable
			if (pass == 0) != isSetTable {
				continue
			}
			if err := decodeSection(b, typeID, payload); err != nil {
				return nil, fmt.Errorf("krs: section[%d] type=0x%04x: %w", i, typeID, err)
			}
		}
	}

	// Defense in depth: the writer is the canonical sorter, but a malicious
	// or buggy producer could ship unsorted entries. Match algorithms binary-
	// search these slices; unsorted input silently hides legitimate rules
	// (CDN-compromise routing bypass). Re-sort every set's reversed slice so
	// search correctness is independent of producer trust.
	for i := range b.Sets {
		s := &b.Sets[i].domainSection.reversed
		if !sort.StringsAreSorted(*s) {
			sort.Strings(*s)
		}
		s = &b.Sets[i].excludeSection.reversed
		if !sort.StringsAreSorted(*s) {
			sort.Strings(*s)
		}
		b.Sets[i].ipv4.canonicalize()
		b.Sets[i].ipv6.canonicalize()
	}
	return b, nil
}

// decodeSection dispatches a section payload to the matching field on b.
// Unknown TypeIDs are logged and skipped (forward-compat).
func decodeSection(b *Bundle, typeID uint16, payload []byte) error {
	switch typeID {
	case typeSetTable:
		names, err := decodeSetTable(payload)
		if err != nil {
			return err
		}
		b.Sets = make([]NamedSet, len(names))
		for i, n := range names {
			b.Sets[i].Name = n
		}
		return nil
	case typeIPv4RangesBySet:
		return decodeIPRangesBySet(b, payload, 4)
	case typeIPv6RangesBySet:
		return decodeIPRangesBySet(b, payload, 16)
	case typeDomainSuffixBySet:
		return decodeDomainBySet(b, payload, false)
	case typeDomainExcludeBySet:
		return decodeDomainBySet(b, payload, true)
	case typeAndroidInstallers, typeAndroidApps, typeWindowsApps, typeDarwinApps:
		return decodeAppSection(b, typeID, payload)
	default:
		slog.Warn("krs: unknown section TypeID, skipping",
			"type_id", fmt.Sprintf("0x%04x", typeID),
			"length", len(payload))
		return nil
	}
}

// decodeDomainBySet reads (u16 set_idx, uvarint(len), reversed-lower utf-8)
// entries until payload is exhausted, distributing each to b.Sets[set_idx]'s
// domainSection or excludeSection.
//
// Payload is assumed sorted by (set_idx, value) — reader trusts the writer
// and assigns each set its contiguous slice without re-sorting.
func decodeDomainBySet(b *Bundle, payload []byte, exclude bool) error {
	pos := 0
	for pos < len(payload) {
		if pos+2 > len(payload) {
			return fmt.Errorf("domain section: truncated set_idx at offset %d", pos)
		}
		setIdx := binary.LittleEndian.Uint16(payload[pos : pos+2])
		pos += 2
		strLen, n := binary.Uvarint(payload[pos:])
		if n <= 0 {
			return fmt.Errorf("domain section: bad uvarint at offset %d", pos)
		}
		pos += n
		// uint64 compare so a hostile length that wraps int stays caught.
		if strLen > uint64(len(payload)-pos) {
			return fmt.Errorf("domain section: value (len=%d) overruns payload at offset %d", strLen, pos)
		}
		val := string(payload[pos : pos+int(strLen)])
		pos += int(strLen)

		if int(setIdx) >= len(b.Sets) {
			return fmt.Errorf("domain section: set_idx=%d out of range (have %d sets)", setIdx, len(b.Sets))
		}
		target := &b.Sets[setIdx].domainSection
		if exclude {
			target = &b.Sets[setIdx].excludeSection
		}
		target.reversed = append(target.reversed, val)
	}
	return nil
}

// decodeSetTable inverse of encodeSetTable.
func decodeSetTable(payload []byte) ([]string, error) {
	if len(payload) < 2 {
		return nil, fmt.Errorf("SetTable payload too short (%d bytes)", len(payload))
	}
	count := binary.LittleEndian.Uint16(payload[0:2])
	pos := 2
	out := make([]string, count)
	for i := range int(count) {
		nameLen, n := binary.Uvarint(payload[pos:])
		if n <= 0 {
			return nil, fmt.Errorf("SetTable: bad uvarint at entry %d", i)
		}
		pos += n
		// uint64 compare so a hostile length that wraps int stays caught.
		if nameLen > uint64(len(payload)-pos) {
			return nil, fmt.Errorf("SetTable: name %d overruns payload (need %d, have %d)",
				i, nameLen, len(payload)-pos)
		}
		out[i] = string(payload[pos : pos+int(nameLen)])
		pos += int(nameLen)
	}
	return out, nil
}
