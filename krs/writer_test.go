package krs_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/kaitu-io/k2-rules/krs"
)

// An empty bundle (no sets, no apps) should serialize to exactly the
// 8-byte header: magic + version + section count.
func TestWriteBundle_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, &krs.Bundle{}); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	want := []byte{
		'K', '2', 'R', 'L',
		0x01, 0x00,
		0x00, 0x00,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteBundle empty:\n got: %x\nwant: %x", buf.Bytes(), want)
	}
}

// One named set with no data emits only a SetTable section.
// Layout:
//
//	[8B hdr] [10B index entry: TypeID=0x0001, off=18, len=9]
//	[9B SetTable: count=1, uvarint(6), "google"]
func TestWriteBundle_OneSet_NoData(t *testing.T) {
	var buf bytes.Buffer
	b := &krs.Bundle{Sets: []krs.NamedSet{{Name: "google"}}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	want := []byte{
		// Header
		'K', '2', 'R', 'L',
		0x01, 0x00,
		0x01, 0x00, // section count = 1
		// Index entry [TypeID=0x0001, off=18, len=9]
		0x01, 0x00,
		18, 0, 0, 0,
		9, 0, 0, 0,
		// SetTable payload: count=1, uvarint(6), "google"
		0x01, 0x00,
		6,
		'g', 'o', 'o', 'g', 'l', 'e',
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteBundle one-set:\n got: %x\nwant: %x", buf.Bytes(), want)
	}
}

// One set with one domain emits SetTable + DomainSuffixBySet, both in
// TypeID-ascending order. Domain is reversed and lowercased at compile time.
//
// Layout:
//
//	[8B hdr] [10B SetTable index] [10B DomainSuffix index]
//	[SetTable: u16(1) + uvarint(6) + "google"] = 9B
//	[DomainSuffix: u16(set_idx=0) + uvarint(10) + "moc.elgoog"] = 13B
func TestWriteBundle_DomainSuffix(t *testing.T) {
	var buf bytes.Buffer
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "google", DomainSuffixes: []string{"google.com"}},
	}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	want := []byte{
		// Header
		'K', '2', 'R', 'L', 0x01, 0x00, 0x02, 0x00,
		// Index entry 0: SetTable (0x0001), off=28, len=9
		0x01, 0x00, 28, 0, 0, 0, 9, 0, 0, 0,
		// Index entry 1: DomainSuffixBySet (0x0012), off=37, len=13
		0x12, 0x00, 37, 0, 0, 0, 13, 0, 0, 0,
		// SetTable payload
		0x01, 0x00, 6, 'g', 'o', 'o', 'g', 'l', 'e',
		// DomainSuffix payload: set_idx=0, uvarint(10), "moc.elgoog"
		0x00, 0x00, 10, 'm', 'o', 'c', '.', 'e', 'l', 'g', 'o', 'o', 'g',
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteBundle domain-suffix:\n got: %x\nwant: %x", buf.Bytes(), want)
	}
}

// Mixed-case domains are lowercased before reversing. Mixed order is sorted
// by (set_idx ASC, value ASC) on the reversed-lower form.
func TestWriteBundle_DomainSuffix_SortsAndLowers(t *testing.T) {
	var buf bytes.Buffer
	// Two sets, second listed first to confirm set_idx follows Sets[] order.
	// Domains in non-sorted, mixed-case order to confirm normalization.
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "alpha", DomainSuffixes: []string{"B.com", "a.com"}},
		{Name: "beta", DomainSuffixes: []string{"C.com"}},
	}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	// After normalization & sort: alpha → [moc.a, moc.b], beta → [moc.c]
	// (entries: set_idx ASC, then reversed-lower string ASC)
	got := buf.Bytes()
	// Find the DomainSuffix section payload by looking at index entry 1.
	if got[18] != 0x12 {
		t.Fatalf("expected DomainSuffix at index[1], got TypeID=0x%02x%02x", got[19], got[18])
	}
	off := int(binary.LittleEndian.Uint32(got[20:24]))
	length := int(binary.LittleEndian.Uint32(got[24:28]))
	payload := got[off : off+length]

	wantPayload := []byte{
		// (set_idx=0, "moc.a")
		0x00, 0x00, 5, 'm', 'o', 'c', '.', 'a',
		// (set_idx=0, "moc.b")
		0x00, 0x00, 5, 'm', 'o', 'c', '.', 'b',
		// (set_idx=1, "moc.c")
		0x01, 0x00, 5, 'm', 'o', 'c', '.', 'c',
	}
	if !bytes.Equal(payload, wantPayload) {
		t.Errorf("DomainSuffix payload:\n got: %x\nwant: %x", payload, wantPayload)
	}
}

// Two sets — names retain caller-supplied order (set_idx 0 → "google", 1 → "youtube").
func TestWriteBundle_TwoSets_PreservesOrder(t *testing.T) {
	var buf bytes.Buffer
	b := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "google"},
		{Name: "youtube"},
	}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	// SetTable payload: 2(count) + 1(uvarint) + 6("google") + 1(uvarint) + 7("youtube") = 17 bytes
	want := []byte{
		'K', '2', 'R', 'L',
		0x01, 0x00,
		0x01, 0x00,
		0x01, 0x00,
		18, 0, 0, 0,
		17, 0, 0, 0,
		0x02, 0x00,
		6, 'g', 'o', 'o', 'g', 'l', 'e',
		7, 'y', 'o', 'u', 't', 'u', 'b', 'e',
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("WriteBundle two-sets:\n got: %x\nwant: %x", buf.Bytes(), want)
	}
}
