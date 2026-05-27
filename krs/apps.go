package krs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

const (
	typeAndroidInstallers uint16 = 0x0100
	typeAndroidApps       uint16 = 0x0101
	typeWindowsApps       uint16 = 0x0200
	typeDarwinApps        uint16 = 0x0300
)

// encodeStringList serializes a sorted []string as concatenated
// (uvarint(len) + utf-8) entries. Empty/whitespace items are skipped.
// Caller is responsible for case-normalization (Windows lowercase happens
// in collectAppSections, not here).
func encodeStringList(items []string) []byte {
	cleaned := normalizeStrings(items, false)
	if len(cleaned) == 0 {
		return nil
	}
	var buf bytes.Buffer
	var vb [binary.MaxVarintLen64]byte
	for _, s := range cleaned {
		n := binary.PutUvarint(vb[:], uint64(len(s)))
		buf.Write(vb[:n])
		buf.WriteString(s)
	}
	return buf.Bytes()
}

// normalizeStrings trims, optionally lowercases, dedups, and sorts.
//
// Also drops all-`*` patterns (`*`, `**`, `***`, …) as defense in depth
// against a validator miss: matchGlob treats any such pattern as "match
// every input", which would route every installed app direct. The
// authoritative reject lives in tools/validate-app-bypass; this is the
// safety net for when bad YAML slips past CI (force-merge, validator
// regression, etc.).
func normalizeStrings(in []string, lower bool) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if lower {
			s = strings.ToLower(s)
		}
		if strings.Trim(s, "*") == "" {
			slog.Warn("krs: dropping all-* app pattern (validator should have caught this)",
				"pattern", s)
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// collectAppSections emits the app-pattern sections for a bundle's Apps.
// Windows entries are lowercased here (compile-time case folding).
func collectAppSections(apps *AppPatterns) []section {
	if apps == nil {
		return nil
	}
	var out []section
	if p := encodeStringList(apps.Android.Installers); len(p) > 0 {
		out = append(out, section{typeAndroidInstallers, p})
	}
	if p := encodeStringList(apps.Android.Apps); len(p) > 0 {
		out = append(out, section{typeAndroidApps, p})
	}
	if p := encodeStringList(normalizeStrings(apps.Windows.Apps, true)); len(p) > 0 {
		out = append(out, section{typeWindowsApps, p})
	}
	if p := encodeStringList(apps.Darwin.Apps); len(p) > 0 {
		out = append(out, section{typeDarwinApps, p})
	}
	return out
}

// decodeAppSection populates the corresponding field on b.Apps for one
// of the app-pattern TypeIDs. b.Apps is lazily allocated.
func decodeAppSection(b *Bundle, typeID uint16, payload []byte) error {
	items, err := decodeStringList(payload)
	if err != nil {
		return err
	}
	if b.Apps == nil {
		b.Apps = &AppPatterns{}
	}
	switch typeID {
	case typeAndroidInstallers:
		b.Apps.Android.Installers = items
	case typeAndroidApps:
		b.Apps.Android.Apps = items
	case typeWindowsApps:
		b.Apps.Windows.Apps = items
	case typeDarwinApps:
		b.Apps.Darwin.Apps = items
	default:
		return fmt.Errorf("decodeAppSection: unexpected TypeID 0x%04x", typeID)
	}
	return nil
}

// decodeStringList parses concatenated (uvarint(len) + utf-8) entries
// until payload is exhausted.
func decodeStringList(payload []byte) ([]string, error) {
	var out []string
	pos := 0
	for pos < len(payload) {
		strLen, n := binary.Uvarint(payload[pos:])
		if n <= 0 {
			return nil, fmt.Errorf("bad uvarint at offset %d", pos)
		}
		pos += n
		// uint64 compare so a hostile length that wraps int stays caught.
		if strLen > uint64(len(payload)-pos) {
			return nil, fmt.Errorf("string at offset %d overruns payload (len=%d)", pos, strLen)
		}
		out = append(out, string(payload[pos:pos+int(strLen)]))
		pos += int(strLen)
	}
	return out, nil
}
