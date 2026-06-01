package krs

import (
	"fmt"
	"net/netip"
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

// TestConstitution_MatchIPAllocs asserts the IP hot path is allocation-free too
// (netip.Addr is a value; contains() binary-searches in place on the mmap).
func TestConstitution_MatchIPAllocs(t *testing.T) {
	db, err := Open(writeTmpBundle(t, bigBundle(2_000, 20_000)))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	set := db.Sets()[0]
	addr := netip.MustParseAddr("10.40.5.7")
	allocs := testing.AllocsPerRun(200, func() {
		_ = set.MatchIP(addr)
	})
	if allocs > 0 {
		t.Fatalf("MatchIP allocates %.1f/op, want 0", allocs)
	}
}

// multiSetBundle builds nSets sets, each with perSetDomains domains + perSetCIDRs
// /24s, names unique. Exercises the O(set count) heap invariant across many sets,
// which the single-set bigBundle gate does not.
func multiSetBundle(nSets, perSetDomains, perSetCIDRs int) *Bundle {
	sets := make([]NamedSet, nSets)
	for s := 0; s < nSets; s++ {
		set := NamedSet{Name: fmt.Sprintf("region%d", s)}
		for i := 0; i < perSetDomains; i++ {
			set.DomainSuffixes = append(set.DomainSuffixes,
				fmt.Sprintf("s%d-d%d.example", s, i))
		}
		for i := 0; i < perSetCIDRs; i++ {
			set.CIDRs = append(set.CIDRs,
				fmt.Sprintf("10.%d.%d.0/24", (s*256+i)/256%256, i%256))
		}
		sets[s] = set
	}
	return &Bundle{Sets: sets}
}

// TestConstitution_TotalHeapBudget asserts the realistic multi-region case: a
// bundle the size of the shipped corpus (many sets, hundreds of thousands of
// rules) must hold < 64 KB of rule-attributable dirty heap after Open. A
// regression to heap-expansion would blow this by megabytes.
func TestConstitution_TotalHeapBudget(t *testing.T) {
	// 25 regions × 6000 domains × 1000 CIDRs ≈ 150k domains + 25k CIDRs on disk.
	path := writeTmpBundle(t, multiSetBundle(25, 6_000, 1_000))

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Realize any lazy work across all sets.
	for _, s := range db.Sets() {
		_ = s.MatchDomainReversed(ReversedParents("s0-d0.example"))
		_ = s.MatchIP(netip.MustParseAddr("10.0.0.1"))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(db)

	var delta uint64
	if after.HeapInuse > before.HeapInuse {
		delta = after.HeapInuse - before.HeapInuse
	}
	db.Close()
	if delta > 64*1024 {
		t.Fatalf("total rule-attributable heap = %dB > 64KB budget (150k domains "+
			"+ 25k CIDRs across 25 sets should be ~O(sets), not O(rules))", delta)
	}
}
