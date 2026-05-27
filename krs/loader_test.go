package krs_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kaitu-io/k2-rules/krs"
)

// Load reads every *.krs file in dir and returns the parsed bundles.
// Missing dir is non-fatal (returns nil, nil).
func TestLoad_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	got, err := krs.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 bundles, got %d", len(got))
	}
}

func TestLoad_MissingDir(t *testing.T) {
	got, err := krs.Load(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatalf("Load(missing): %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestLoad_MultipleBundles(t *testing.T) {
	dir := t.TempDir()
	writeBundleFile(t, dir, "cn.krs", &krs.Bundle{
		Sets: []krs.NamedSet{{Name: "google", DomainSuffixes: []string{"google.com"}}},
	})
	writeBundleFile(t, dir, "ir.krs", &krs.Bundle{
		Sets: []krs.NamedSet{{Name: "telegram", DomainSuffixes: []string{"telegram.org"}}},
	})
	// Non-krs files must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := krs.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 bundles, got %d", len(got))
	}
}

// A truly-empty (0 bytes) .krs file fails the header-length check inside
// ReadBundle. Load must skip it (warning log only) and still return the
// good bundles. Caught at byte-zero rather than panic on header parse.
func TestLoad_EmptyFileSkipped(t *testing.T) {
	dir := t.TempDir()
	writeBundleFile(t, dir, "good.krs", &krs.Bundle{
		Sets: []krs.NamedSet{{Name: "ok"}},
	})
	if err := os.WriteFile(filepath.Join(dir, "empty.krs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := krs.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 || got[0].Sets[0].Name != "ok" {
		t.Errorf("expected one good bundle (empty.krs skipped), got %+v", got)
	}
}

// Corrupt files do not abort Load — they are skipped with a warning log.
// Graceful skip aligns with k2's existing rule.Load behavior.
func TestLoad_CorruptFileSkipped(t *testing.T) {
	dir := t.TempDir()
	writeBundleFile(t, dir, "good.krs", &krs.Bundle{
		Sets: []krs.NamedSet{{Name: "ok"}},
	})
	if err := os.WriteFile(filepath.Join(dir, "bad.krs"), []byte("not a krs file"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := krs.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 || got[0].Sets[0].Name != "ok" {
		t.Errorf("expected one good bundle, got %+v", got)
	}
}

// Index merges sets from multiple bundles into a single name→*NamedSet map.
// Last bundle wins on name collision (k2 rule.Index parity).
func TestIndex_MergesBundlesLastWins(t *testing.T) {
	b1 := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "google", DomainSuffixes: []string{"old-google.com"}},
		{Name: "telegram", DomainSuffixes: []string{"telegram.org"}},
	}}
	b2 := &krs.Bundle{Sets: []krs.NamedSet{
		{Name: "google", DomainSuffixes: []string{"new-google.com"}},
	}}
	round := func(b *krs.Bundle) *krs.Bundle {
		var buf bytes.Buffer
		if err := krs.WriteBundle(&buf, b); err != nil {
			t.Fatal(err)
		}
		out, err := krs.ReadBundle(buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	idx := krs.Index([]*krs.Bundle{round(b1), round(b2)})
	if len(idx) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(idx))
	}
	if !idx["google"].MatchDomain("new-google.com") {
		t.Error("google: expected last-wins, but new-google.com didn't match")
	}
	if idx["google"].MatchDomain("old-google.com") {
		t.Error("google: stale entry leaked through")
	}
	if !idx["telegram"].MatchDomain("telegram.org") {
		t.Error("telegram: lookup failed")
	}
}

func writeBundleFile(t *testing.T, dir, name string, b *krs.Bundle) {
	t.Helper()
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
