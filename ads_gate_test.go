package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func day(n int) time.Time {
	return time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC).AddDate(0, 0, n)
}

func testGate() *adsGate {
	return newAdsGate([]string{"www.google.com", "mybank.co.uk", "kaitu.io"})
}

func TestAdsGateReject(t *testing.T) {
	g := testGate()
	blocked := []string{
		"www.google.com", // exact never-block host
		"google.com",     // parent of a never-block host
		"kaitu.io",
		"mybank.co.uk",
		"com", "uk", // bare TLD
		"co.uk", "github.io", "cloudfront.net", // public suffixes, ICANN and private
		"1.2.3.4", "2001:db8::1", // addresses
		"localhost", "a..b.com", ".com", "bad domain.com", "x.y",
	}
	for _, d := range blocked {
		if g.reject(d) == "" {
			t.Errorf("%q accepted, want rejected", d)
		}
	}
	allowed := []string{
		"doubleclick.net",
		"ads.google.com", // a subdomain of a protected apex stays blockable
		"ad.kaitu.io",
		"tracker.mybank.co.uk",
		"e.qq.com", "51.la", "s.360.cn", "ad_server.example.com",
	}
	for _, d := range allowed {
		if reason := g.reject(d); reason != "" {
			t.Errorf("%q rejected (%s), want accepted", d, reason)
		}
	}
}

// run feeds one day's upstream list through reconcileAds and returns the
// emitted domains as a comma-joined string plus the report.
func run(t *testing.T, ledger *map[string]adsLedgerRow, n int, upstream ...string) (string, adsReport) {
	t.Helper()
	active, next, rep := reconcileAds(upstream, *ledger, testGate(), day(n))
	*ledger = next
	return strings.Join(active, ","), rep
}

func TestReconcileAdsQuarantine(t *testing.T) {
	ledger := map[string]adsLedgerRow{"old.example": {Domain: "old.example", FirstSeen: adsBaseline}}

	// A new upstream entry is recorded, not emitted.
	got, rep := run(t, &ledger, 0, "old.example", "new.example")
	if got != "old.example" || len(rep.Added) != 1 || rep.Pending != 1 {
		t.Fatalf("day 0: active=%q report=%+v", got, rep)
	}
	// Still held on the last day of the quarantine.
	if got, _ := run(t, &ledger, 13, "old.example", "new.example"); got != "old.example" {
		t.Fatalf("day 13: active=%q, new.example must still be held", got)
	}
	// Emitted from day 14 on.
	got, rep = run(t, &ledger, 14, "old.example", "new.example")
	if got != "new.example,old.example" || len(rep.Graduated) != 1 {
		t.Fatalf("day 14: active=%q report=%+v", got, rep)
	}
	// Removal upstream takes effect immediately.
	got, rep = run(t, &ledger, 15, "new.example")
	if got != "new.example" || len(rep.Removed) != 1 {
		t.Fatalf("day 15: active=%q report=%+v", got, rep)
	}
}

func TestReconcileAdsWithdrawnEntryNeverShips(t *testing.T) {
	ledger := map[string]adsLedgerRow{}
	run(t, &ledger, 0, "mistake.example")
	// Upstream reverts on day 5: the entry is forgotten.
	if _, rep := run(t, &ledger, 5); len(rep.Removed) != 1 || len(ledger) != 0 {
		t.Fatalf("day 5: report=%+v ledger=%v", rep, ledger)
	}
	// It comes back on day 6: the clock restarts, so day 14 is too early...
	run(t, &ledger, 6, "mistake.example")
	if got, _ := run(t, &ledger, 14, "mistake.example"); got != "" {
		t.Fatalf("day 14: %q emitted on the original clock, want held until day 20", got)
	}
	// ...and day 20 is when it matures.
	if got, _ := run(t, &ledger, 20, "mistake.example"); got != "mistake.example" {
		t.Fatalf("day 20: active=%q", got)
	}
}

func TestReconcileAdsPoisonedEntryNeverShips(t *testing.T) {
	ledger := map[string]adsLedgerRow{}
	_, rep := run(t, &ledger, 0, "google.com", "co.uk", "ads.google.com")
	if len(rep.NewRejected) != 2 {
		t.Fatalf("day 0: want google.com and co.uk rejected, got %v", rep.NewRejected)
	}
	// Reported once, not every night.
	if _, rep := run(t, &ledger, 1, "google.com", "co.uk", "ads.google.com"); len(rep.NewRejected) != 0 {
		t.Fatalf("day 1: rejection reported again: %v", rep.NewRejected)
	}
	// No amount of waiting gets a rejected entry out.
	if got, _ := run(t, &ledger, 400, "google.com", "co.uk", "ads.google.com"); got != "ads.google.com" {
		t.Fatalf("day 400: active=%q, want only ads.google.com", got)
	}
}

func TestReconcileAdsNeverBlockAppliesToBaseline(t *testing.T) {
	// An entry that was already active is dropped as soon as never-block covers it.
	ledger := map[string]adsLedgerRow{"kaitu.io": {Domain: "kaitu.io", FirstSeen: adsBaseline}}
	got, rep := run(t, &ledger, 0, "kaitu.io")
	if got != "" || len(rep.NewRejected) != 1 {
		t.Fatalf("active=%q report=%+v", got, rep)
	}
}

func TestReconcileAdsBadDatesAreHeld(t *testing.T) {
	for _, firstSeen := range []string{"garbage", "", "2099-01-01", "21/11/2026"} {
		ledger := map[string]adsLedgerRow{"x.example": {Domain: "x.example", FirstSeen: firstSeen}}
		got, _ := run(t, &ledger, 0, "x.example")
		if got != "" {
			t.Errorf("first_seen %q: emitted, want held", firstSeen)
		}
		if ledger["x.example"].FirstSeen != day(0).Format(adsDateLayout) {
			t.Errorf("first_seen %q: not reset to today, got %q", firstSeen, ledger["x.example"].FirstSeen)
		}
	}
}

func TestReconcileAdsNormalisesAndDedupes(t *testing.T) {
	ledger := map[string]adsLedgerRow{"old.example": {Domain: "old.example", FirstSeen: adsBaseline}}
	got, _ := run(t, &ledger, 0, " OLD.example. ", "old.example", "")
	if got != "old.example" || len(ledger) != 1 {
		t.Fatalf("active=%q ledger=%v", got, ledger)
	}
}

func TestAdsLedgerRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.tsv")
	want := map[string]adsLedgerRow{
		"b.example":  {Domain: "b.example", FirstSeen: "2026-11-21"},
		"a.example":  {Domain: "a.example", FirstSeen: adsBaseline},
		"google.com": {Domain: "google.com", FirstSeen: "2026-11-22", Rejected: "would block www.google.com"},
	}
	if err := writeAdsLedger(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := readAdsLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d", len(got), len(want))
	}
	for d, row := range want {
		if got[d] != row {
			t.Errorf("%s: got %+v, want %+v", d, got[d], row)
		}
	}

	if _, err := readAdsLedger(filepath.Join(t.TempDir(), "absent.tsv")); err == nil {
		t.Error("missing ledger read as empty, want error")
	}
	for name, body := range map[string]string{
		"duplicate": "a.example\tbaseline\na.example\tbaseline\n",
		"no date":   "a.example\n",
		"too wide":  "a.example\tbaseline\tx\ty\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readAdsLedger(path); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
}

// The committed data must agree with itself: the build would otherwise start
// by silently dropping part of the baseline or by failing validateAds.
func TestCommittedAdsData(t *testing.T) {
	ledger, err := readAdsLedger("ads/ledger.tsv")
	if err != nil {
		t.Fatal(err)
	}
	neverBlock, err := readHostList("ads/never-block.txt")
	if err != nil {
		t.Fatal(err)
	}
	listed := make(map[string]bool, len(neverBlock))
	for _, h := range neverBlock {
		listed[h] = true
	}
	for _, h := range adsMustNotBlock {
		if !listed[h] {
			t.Errorf("ads/never-block.txt lacks %s (adsMustNotBlock)", h)
		}
	}
	gate := newAdsGate(neverBlock)
	for _, anchors := range adsAnchors {
		for _, a := range anchors {
			if reason := gate.reject(a); reason != "" {
				t.Errorf("anchor %s is rejected by the gate (%s) — the build could never pass", a, reason)
			}
			if _, ok := ledger[a]; !ok {
				t.Errorf("anchor %s is not in the ledger", a)
			}
		}
	}
	for d, row := range ledger {
		if reason := gate.reject(d); reason != row.Rejected {
			t.Errorf("ledger row %s: recorded rejection %q, gate says %q", d, row.Rejected, reason)
		}
	}
}
