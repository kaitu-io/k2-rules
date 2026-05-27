package krs

import (
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

// toASCIIDomain normalizes a domain string to its canonical ASCII (LDH)
// form via IDNA — Unicode IDN labels become punycode, ASCII is case-folded,
// trailing FQDN dot is stripped. Returns ok=false for inputs that aren't
// valid DNS hostnames (underscores, wildcards, ports, malformed labels,
// arbitrary garbage), which the caller must drop rather than corrupt.
//
// Why this exists: stored suffix entries are byte-reversed by reverseASCII
// for binary search. reverseASCII is byte-level — running it on multi-byte
// UTF-8 produces non-roundtrippable garbage. The post-DNS form of an IDN
// host is always punycode (idna.Lookup.ToASCII output), so storing punycode
// is the only form that round-trips against real runtime queries.
//
// Uses idna.Lookup (strict): the same profile Go's net package uses before
// emitting DNS queries, so writer-side normalization matches what the
// matcher receives at runtime.
func toASCIIDomain(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
		if s == "" {
			return "", false
		}
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", false
	}
	return ascii, true
}

// domainSection holds a sorted list of reversed-lowercase domain suffixes
// for one NamedSet. Match does a single binary search.
type domainSection struct {
	// reversed is sorted ascending. Each entry is the reversed-lowercased
	// form of a domain suffix, e.g. "google.com" → "moc.elgoog".
	reversed []string
}

// Match reports whether host hits any suffix rule in this section.
//
// Semantics: rule "google.com" matches "google.com" and any subdomain
// like "mail.google.com", but NOT "fakegoogle.com" (suffix must be on
// a label boundary).
//
// Algorithm: walk host's parent suffixes (host, then host with the
// leftmost label stripped, repeat) and exact-match each against the
// reversed table. A single binary search "largest entry ≤ rq" is unsafe
// when the table contains both a parent and a descendant suffix in the
// same set — a lex-smaller sibling sub-suffix can sit between parent
// and query and mask the parent match.
func (s *domainSection) Match(host string) bool {
	if len(s.reversed) == 0 {
		return false
	}
	// Normalize to the same ASCII LDH form the writer stored: IDN →
	// punycode, case-folded, trailing dot stripped. Invalid hostnames
	// (underscores, malformed labels) can't appear in the suffix table
	// either (writer drops them), so they trivially miss.
	h, ok := toASCIIDomain(host)
	if !ok {
		return false
	}
	for h != "" {
		rq := reverseASCII(h)
		idx := sort.SearchStrings(s.reversed, rq)
		if idx < len(s.reversed) && s.reversed[idx] == rq {
			return true
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 {
			return false
		}
		h = h[dot+1:]
	}
	return false
}

// MatchDomain reports whether host should be routed by this set.
// Excludes take priority — a host matching ExcludeDomains is rejected
// even when it would otherwise hit DomainSuffixes.
func (s *NamedSet) MatchDomain(host string) bool {
	if s.excludeSection.Match(host) {
		return false
	}
	return s.domainSection.Match(host)
}
