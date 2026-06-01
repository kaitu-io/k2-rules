package krs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMmapReadOnly_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blob")
	want := []byte("K2RL-mmap-test-payload")
	if err := os.WriteFile(p, want, 0o644); err != nil {
		t.Fatal(err)
	}
	data, closeFn, err := mmapReadOnly(p)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	if string(data) != string(want) {
		t.Fatalf("mmap content=%q want %q", data, want)
	}
}

func TestMmapReadOnly_EmptyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	data, closeFn, err := mmapReadOnly(p)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	if len(data) != 0 {
		t.Fatalf("empty file mapped to %d bytes", len(data))
	}
}
