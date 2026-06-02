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

// writeKRSAt writes a bundle to a named .krs path inside dir, so the
// floor-check tests can control the region (filename) under test.
func writeKRSAt(t *testing.T, path string, b *krs.Bundle) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := krs.WriteBundle(f, b); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRuleFloor_RejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	writeKRSAt(t, filepath.Join(dir, "empty.krs"), &krs.Bundle{Sets: []krs.NamedSet{{Name: "s"}}})
	if err := checkRuleFloor(dir, nil); err == nil {
		t.Fatal("expected empty.krs (0 rules) to fail the floor, got nil")
	}
}

func TestCheckRuleFloor_RejectsCNRegression(t *testing.T) {
	dir := t.TempDir()
	// New cn has 1 rule; previous manifest claimed 100 → 1 < 80 → fail.
	writeKRSAt(t, filepath.Join(dir, "cn.krs"), &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "s", DomainSuffixes: []string{"a.com"}},
	}})
	prev := map[string]int{"cn": 100}
	if err := checkRuleFloor(dir, prev); err == nil {
		t.Fatal("expected cn regression (1 vs 100) to fail, got nil")
	}
}

func TestCheckRuleFloor_PassesHealthy(t *testing.T) {
	dir := t.TempDir()
	writeKRSAt(t, filepath.Join(dir, "cn.krs"), &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "s", DomainSuffixes: []string{"a.com", "b.com", "c.com", "d.com"}},
	}})
	prev := map[string]int{"cn": 4}
	if err := checkRuleFloor(dir, prev); err != nil {
		t.Fatalf("healthy cn should pass: %v", err)
	}
}
