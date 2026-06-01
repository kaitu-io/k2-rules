package krs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// writeTmpBundle writes b to a temp .krs and returns its path.
func writeTmpBundle(t *testing.T, b *Bundle) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteBundle(&buf, b); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "b.krs")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOpen_NamesAndClose(t *testing.T) {
	b := &Bundle{Sets: []NamedSet{
		{Name: "cn", DomainSuffixes: []string{"qq.com"}, CIDRs: []string{"1.1.1.0/24"}},
		{Name: "x", DomainSuffixes: []string{"foo.org"}},
	}}
	db, err := Open(writeTmpBundle(t, b))
	if err != nil {
		t.Fatal(err)
	}
	if got := db.SetNames(); len(got) != 2 || got[0] != "cn" || got[1] != "x" {
		t.Fatalf("SetNames=%v", got)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestOpen_BadMagic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.krs")
	if err := os.WriteFile(p, []byte("NOPExxxx"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil {
		t.Fatal("expected error on bad magic")
	}
}
