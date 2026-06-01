package krs

import (
	"fmt"
	"runtime"
	"testing"
)

// bigBundle builds a bundle with nDomains synthetic domains + nCIDRs in one set.
func bigBundle(nDomains, nCIDRs int) *Bundle {
	s := NamedSet{Name: "cn"}
	for i := 0; i < nDomains; i++ {
		s.DomainSuffixes = append(s.DomainSuffixes, fmt.Sprintf("d%d-host.example", i))
	}
	for i := 0; i < nCIDRs; i++ {
		s.CIDRs = append(s.CIDRs, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	return &Bundle{Sets: []NamedSet{s}}
}

// TestConstitution_HeapSlopeFlat asserts that Open's resident heap does NOT
// scale with rule count: a 50x larger bundle must not add >8KB of heap.
func TestConstitution_HeapSlopeFlat(t *testing.T) {
	small := writeTmpBundle(t, bigBundle(1_000, 200))
	large := writeTmpBundle(t, bigBundle(50_000, 5_000))

	heapAfterOpen := func(path string) uint64 {
		runtime.GC()
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		db, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		// touch one lookup so lazy work (if any) is realized
		_ = db.Sets()[0].MatchDomainReversed(ReversedParents("d1-host.example"))
		runtime.GC()
		runtime.ReadMemStats(&b)
		// db must stay mapped through the measurement, else its heap drops out
		// of HeapInuse before we read it. KeepAlive guarantees this (a dead
		// local would let the GC reclaim it).
		runtime.KeepAlive(db)
		// HeapInuse can decrease (GC releases pages); treat a decrease as 0.
		var h uint64
		if b.HeapInuse > a.HeapInuse {
			h = b.HeapInuse - a.HeapInuse
		}
		db.Close()
		return h
	}
	hSmall := heapAfterOpen(small)
	hLarge := heapAfterOpen(large)

	// 50x more rules must not add >8KB heap (constitution budget per region).
	if hLarge > hSmall+8*1024 {
		t.Fatalf("heap scales with rules: small=%dB large=%dB (delta %dB > 8KB)",
			hSmall, hLarge, hLarge-hSmall)
	}
}

// TestConstitution_MatchAllocs asserts the hot path is allocation-free.
func TestConstitution_MatchAllocs(t *testing.T) {
	db, err := Open(writeTmpBundle(t, bigBundle(20_000, 2_000)))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	set := db.Sets()[0]
	parents := ReversedParents("d12345-host.example") // computed once, outside
	allocs := testing.AllocsPerRun(200, func() {
		_ = set.MatchDomainReversed(parents)
	})
	if allocs > 0 {
		t.Fatalf("MatchDomainReversed allocates %.1f/op, want 0", allocs)
	}
}
