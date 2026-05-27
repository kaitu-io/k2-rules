package krs_test

import (
	"bytes"
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
