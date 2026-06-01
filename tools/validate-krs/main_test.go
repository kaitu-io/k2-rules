package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/kaitu-io/k2-rules/krs"
)

func writeKRS(t *testing.T, b *krs.Bundle) (path string, raw []byte) {
	t.Helper()
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "x.krs")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, buf.Bytes()
}

func TestValidateFile_Good(t *testing.T) {
	p, _ := writeKRS(t, &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "cn", DomainSuffixes: []string{"qq.com", "weixin.qq.com"}, CIDRs: []string{"1.1.1.0/24"}},
		{Name: "os", DomainSuffixes: []string{"google.com"}},
	}})
	if err := validateFile(p); err != nil {
		t.Fatalf("good bundle rejected: %v", err)
	}
}

func TestValidateFile_Garbage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.krs")
	if err := os.WriteFile(p, []byte("NOTAKRSFILE!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateFile(p); err == nil {
		t.Fatal("garbage bundle accepted by validator")
	}
}

// The whole point of the gate: a bundle whose domain payload is missing its
// offset-index section (a Version-1 / pre-index artifact) must be rejected,
// because krs.Open — the runtime path — cannot read it. This is the deploy-
// ordering trap (shipping index-less krs.tar.gz) turned into a hard CI failure.
func TestValidateFile_DomainPayloadMissingIndex(t *testing.T) {
	_, raw := writeKRS(t, &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "cn", DomainSuffixes: []string{"qq.com"}},
	}})
	// Hide the domain-suffix-index section by corrupting its TypeID in the
	// section table (0x0014 -> 0x9999), so Open sees payload without index.
	n := int(binary.LittleEndian.Uint16(raw[6:8]))
	for i := 0; i < n; i++ {
		at := 8 + i*10
		if binary.LittleEndian.Uint16(raw[at:at+2]) == 0x0014 {
			binary.LittleEndian.PutUint16(raw[at:at+2], 0x9999)
		}
	}
	p := filepath.Join(t.TempDir(), "noidx.krs")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateFile(p); err == nil {
		t.Fatal("index-less bundle accepted — gate would let an unreadable artifact reach the CDN")
	}
}
