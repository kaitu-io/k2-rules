package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kaitu-io/k2-rules/krs"
)

func writeTestKRS(t *testing.T, path string, b *krs.Bundle) {
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

func TestBuildManifest_SchemaV2(t *testing.T) {
	dir := t.TempDir()
	writeTestKRS(t, filepath.Join(dir, "cn.krs"), &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "s", DomainSuffixes: []string{"a.com", "b.com", "c.com"}},
	}})

	m := buildManifest(dir)

	if m.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d, want 2", m.SchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339, m.Version); err != nil {
		t.Errorf("Version %q not RFC3339: %v", m.Version, err)
	}
	cn, ok := m.Bundles["cn"]
	if !ok {
		t.Fatal("cn bundle missing from manifest")
	}
	if cn.RuleCount != 3 {
		t.Errorf("cn.RuleCount = %d, want 3", cn.RuleCount)
	}
	if cn.SHA256 == "" || cn.Size == 0 {
		t.Errorf("cn sha/size not populated: %+v", cn)
	}
}

// TestBuildManifest_KRSWinsSharedKey pins the precedence invariant: when a
// region has both .k2b and .krs (shared basename key), the manifest must carry
// the .krs sha/size/ruleCount — that's what the new client fetches and verifies.
func TestBuildManifest_KRSWinsSharedKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "overseas.k2b"), []byte("legacy-k2b-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeTestKRS(t, filepath.Join(dir, "overseas.krs"), &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "s", DomainSuffixes: []string{"a.com", "b.com"}},
	}})

	m := buildManifest(dir)
	ov, ok := m.Bundles["overseas"]
	if !ok {
		t.Fatal("overseas key missing")
	}
	krsBytes, _ := os.ReadFile(filepath.Join(dir, "overseas.krs"))
	sum := sha256.Sum256(krsBytes)
	wantSHA := fmt.Sprintf("%x", sum)
	if ov.SHA256 != wantSHA {
		t.Errorf("overseas sha = %q, want the .krs sha %q (.krs must win shared key)", ov.SHA256, wantSHA)
	}
	if ov.RuleCount != 2 {
		t.Errorf("overseas ruleCount = %d, want 2 (from .krs)", ov.RuleCount)
	}
	if ov.Size != int64(len(krsBytes)) {
		t.Errorf("overseas size = %d, want %d (.krs size)", ov.Size, len(krsBytes))
	}
}
