package krs

import (
	"encoding/binary"
	"fmt"
	"log/slog"
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

		if err := decodeSection(b, typeID, payload); err != nil {
			return nil, fmt.Errorf("krs: section[%d] type=0x%04x: %w", i, typeID, err)
		}
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
		if pos+int(strLen) > len(payload) {
			return fmt.Errorf("domain section: value overruns payload at offset %d", pos)
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
		if pos+int(nameLen) > len(payload) {
			return nil, fmt.Errorf("SetTable: name %d overruns payload (need %d, have %d)",
				i, nameLen, len(payload)-pos)
		}
		out[i] = string(payload[pos : pos+int(nameLen)])
		pos += int(nameLen)
	}
	return out, nil
}
