package krs

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// benchSetup builds one large set (50k domains + 10k /24s) and returns the same
// data through both the heap reader and the mmap reader, so benchmarks measure
// index performance of the two paths on identical input. The disk path is the
// constitution's runtime path; the heap path is the reference.
func benchSetup(b *testing.B) (heapSet, diskSet Matcher, cleanup func()) {
	b.Helper()
	bundle := bigBundle(50_000, 10_000)
	var buf bytes.Buffer
	if err := WriteBundle(&buf, bundle); err != nil {
		b.Fatal(err)
	}
	heap, err := ReadBundle(buf.Bytes())
	if err != nil {
		b.Fatal(err)
	}
	p := filepath.Join(b.TempDir(), "bench.krs")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		b.Fatal(err)
	}
	db, err := Open(p)
	if err != nil {
		b.Fatal(err)
	}
	return &heap.Sets[0], db.Sets()[0], func() { db.Close() }
}

func BenchmarkMatchDomain_Heap(b *testing.B) {
	h, _, done := benchSetup(b)
	defer done()
	parents := ReversedParents("d25000-host.example") // mid-table hit
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.MatchDomainReversed(parents)
	}
}

func BenchmarkMatchDomain_Disk(b *testing.B) {
	_, d, done := benchSetup(b)
	defer done()
	parents := ReversedParents("d25000-host.example")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.MatchDomainReversed(parents)
	}
}

func BenchmarkMatchIP_Heap(b *testing.B) {
	h, _, done := benchSetup(b)
	defer done()
	addr := netip.MustParseAddr("10.20.100.5") // hits 10.20.100.0/24
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.MatchIP(addr)
	}
}

func BenchmarkMatchIP_Disk(b *testing.B) {
	_, d, done := benchSetup(b)
	defer done()
	addr := netip.MustParseAddr("10.20.100.5")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.MatchIP(addr)
	}
}
