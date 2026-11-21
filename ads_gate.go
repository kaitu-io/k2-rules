package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// The `ads` set is rejected by the client, and its only source is an upstream
// community list we do not control. Two automatic gates stand between that
// list and a user, so a mistaken or poisoned upstream entry cannot ship
// without a human reviewing every diff:
//
//  1. Shape + never-block (adsGate): an entry is dropped if it is not a
//     plausible single host (public suffix, bare TLD, IP literal, ...) or if
//     blocking it would also block a host on ads/never-block.txt.
//  2. Quarantine (reconcileAds): an entry upstream adds is only recorded, with
//     the date it first appeared. It takes effect once it has stayed in the
//     upstream list for adsQuarantine. If upstream withdraws it meanwhile it
//     is forgotten, having never reached a user; if it comes back, the clock
//     starts again. Removals take effect immediately.
//
// The state — when each entry was first seen — is ads/ledger.tsv, committed
// to master by CI. Its git history is the record of what upstream changed.

// adsQuarantine is how long a new upstream entry must survive before it is
// emitted.
const adsQuarantine = 14 * 24 * time.Hour

// adsBaseline marks ledger rows that predate the quarantine: the entries
// present when the ledger was created. They are active from the start.
const adsBaseline = "baseline"

const adsDateLayout = "2006-01-02"

// adsLedgerRow is one upstream entry we have seen.
type adsLedgerRow struct {
	Domain    string
	FirstSeen string // adsBaseline or YYYY-MM-DD (UTC)
	Rejected  string // why adsGate dropped it; "" when it passes
}

// adsReport summarises one reconcile run.
type adsReport struct {
	Active      int
	Pending     int
	Added       []string // first seen this run, now in quarantine
	Graduated   []string // left quarantine this run
	Removed     []string // withdrawn upstream this run
	NewRejected []string // newly dropped by the gate: "domain (reason)"
}

// adsGate decides whether a single entry may ever be emitted.
type adsGate struct {
	// covered maps every never-block host and each of its parent suffixes to
	// the never-block host it belongs to. An entry found here would, by
	// suffix match, block that host.
	covered map[string]string
}

func newAdsGate(neverBlock []string) *adsGate {
	g := &adsGate{covered: make(map[string]string)}
	for _, host := range neverBlock {
		for suffix := host; suffix != ""; {
			if _, ok := g.covered[suffix]; !ok {
				g.covered[suffix] = host
			}
			dot := strings.IndexByte(suffix, '.')
			if dot < 0 {
				break
			}
			suffix = suffix[dot+1:]
		}
	}
	return g
}

// reject returns why domain must not be emitted, or "" if it may be.
func (g *adsGate) reject(domain string) string {
	if reason := adsShapeProblem(domain); reason != "" {
		return reason
	}
	if host, ok := g.covered[domain]; ok {
		return "would block " + host
	}
	return ""
}

// adsShapeProblem rejects entries that cannot be one advertiser's host:
// anything a suffix match would turn into a whole TLD, a whole public suffix
// (co.uk, github.io, cloudfront.net) or an address.
func adsShapeProblem(domain string) string {
	if len(domain) < 4 || len(domain) > 253 {
		return "implausible length"
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return "IP literal"
	}
	if !strings.Contains(domain, ".") {
		return "single label"
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return "malformed label"
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "invalid character"
			}
		}
	}
	if suffix, _ := publicsuffix.PublicSuffix(domain); suffix == domain {
		return "public suffix"
	}
	return ""
}

// reconcileAds applies both gates to the current upstream list. It returns
// the domains to emit, the ledger to persist, and a report. It never fails:
// an entry it cannot vouch for is held back, not escalated.
func reconcileAds(upstream []string, ledger map[string]adsLedgerRow, gate *adsGate, now time.Time) ([]string, map[string]adsLedgerRow, adsReport) {
	today := now.UTC().Format(adsDateLayout)
	next := make(map[string]adsLedgerRow, len(upstream))
	var active []string
	var rep adsReport

	for _, raw := range upstream {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if domain == "" {
			continue
		}
		if _, dup := next[domain]; dup {
			continue
		}
		row, known := ledger[domain]
		if !known {
			row = adsLedgerRow{Domain: domain, FirstSeen: today}
			rep.Added = append(rep.Added, domain)
		}
		matured, valid := adsMatured(row.FirstSeen, now)
		if !valid {
			// An unreadable date must not pass as an old one.
			row.FirstSeen, matured = today, false
		}

		reason := gate.reject(domain)
		if reason != "" && row.Rejected == "" {
			rep.NewRejected = append(rep.NewRejected, fmt.Sprintf("%s (%s)", domain, reason))
		}
		row.Rejected = reason
		next[domain] = row

		switch {
		case reason != "":
		case matured:
			active = append(active, domain)
			if known && row.FirstSeen != adsBaseline && adsGraduatesToday(row.FirstSeen, now) {
				rep.Graduated = append(rep.Graduated, domain)
			}
		default:
			rep.Pending++
		}
	}
	for domain := range ledger {
		if _, still := next[domain]; !still {
			rep.Removed = append(rep.Removed, domain)
		}
	}

	sort.Strings(active)
	sort.Strings(rep.Added)
	sort.Strings(rep.Graduated)
	sort.Strings(rep.Removed)
	sort.Strings(rep.NewRejected)
	rep.Active = len(active)
	return active, next, rep
}

// adsMatured reports whether an entry first seen on firstSeen has served its
// quarantine. valid is false when firstSeen is neither adsBaseline nor a date,
// or lies in the future.
func adsMatured(firstSeen string, now time.Time) (matured, valid bool) {
	if firstSeen == adsBaseline {
		return true, true
	}
	seen, err := time.Parse(adsDateLayout, firstSeen)
	if err != nil || seen.After(now) {
		return false, false
	}
	return !now.UTC().Truncate(24 * time.Hour).Before(seen.Add(adsQuarantine)), true
}

// adsGraduatesToday reports whether today is the first day firstSeen counts
// as matured — used only for the report.
func adsGraduatesToday(firstSeen string, now time.Time) bool {
	seen, err := time.Parse(adsDateLayout, firstSeen)
	if err != nil {
		return false
	}
	return now.UTC().Truncate(24 * time.Hour).Equal(seen.Add(adsQuarantine))
}

// readAdsLedger reads ads/ledger.tsv: "domain<TAB>first_seen[<TAB>rejected]".
// A missing file is an error, never an empty ledger — an empty ledger would
// put the whole upstream list back into quarantine.
func readAdsLedger(path string) (map[string]adsLedgerRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ledger := make(map[string]adsLedgerRow)
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		if strings.TrimSpace(text) == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) < 2 || len(fields) > 3 || fields[0] == "" || fields[1] == "" {
			return nil, fmt.Errorf("%s:%d: want domain<TAB>first_seen[<TAB>rejected], got %q", path, line, text)
		}
		row := adsLedgerRow{Domain: fields[0], FirstSeen: fields[1]}
		if len(fields) == 3 {
			row.Rejected = fields[2]
		}
		if _, dup := ledger[row.Domain]; dup {
			return nil, fmt.Errorf("%s:%d: duplicate domain %q", path, line, row.Domain)
		}
		ledger[row.Domain] = row
	}
	return ledger, scanner.Err()
}

const adsLedgerHeader = `# ads ledger — machine-written by the nightly build, do not edit by hand.
# One row per entry currently in the upstream ads list:
#   domain <TAB> first_seen <TAB> rejected-reason (only when the gate drops it)
# first_seen is "baseline" or the UTC date the entry first appeared; an entry
# is emitted into ads.krs once it is 14 days old and not rejected.
# See ads_gate.go.
`

func writeAdsLedger(path string, ledger map[string]adsLedgerRow) error {
	domains := make([]string, 0, len(ledger))
	for d := range ledger {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	var b strings.Builder
	b.WriteString(adsLedgerHeader)
	for _, d := range domains {
		row := ledger[d]
		b.WriteString(row.Domain + "\t" + row.FirstSeen)
		if row.Rejected != "" {
			b.WriteString("\t" + row.Rejected)
		}
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// readHostList reads one lowercase host per line, ignoring blanks and
// '#' comments (whole-line or trailing).
func readHostList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hosts []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		if host := strings.ToLower(strings.TrimSpace(line)); host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts, scanner.Err()
}
