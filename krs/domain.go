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
// for one NamedSet. The hot-path match goes through matchReversed (takes
// pre-reversed parent list); Match(host) is the convenience wrapper.
type domainSection struct {
	// reversed is sorted ascending. Each entry is the reversed-lowercased
	// form of a domain suffix, e.g. "google.com" → "moc.elgoog".
	reversed []string
}

// ReversedParents normalizes host to ASCII-LDH once (IDN→punycode, case-fold,
// strip trailing dot) and returns the reversed forms of host and each parent
// suffix, longest first. Returns nil for non-hostnames. Hoisted out of the
// per-set match path so a consumer pays IDNA + reversal once per lookup, not
// once per set (constitution rule 5).
func ReversedParents(host string) []string {
	h, ok := toASCIIDomain(host)
	if !ok {
		return nil
	}
	out := make([]string, 0, strings.Count(h, ".")+1)
	for h != "" {
		out = append(out, reverseASCII(h))
		dot := strings.IndexByte(h, '.')
		if dot < 0 {
			break
		}
		h = h[dot+1:]
	}
	return out
}

// matchReversed reports whether any pre-reversed parent suffix exactly hits
// this section's sorted table. Allocation-free.
//
// Algorithm: walk the pre-reversed parent list (host, then each parent suffix,
// longest first) and exact-match each against the sorted reversed table. A
// single binary search "largest entry ≤ rq" is unsafe when the table contains
// both a parent and a descendant suffix in the same set — a lex-smaller
// sibling sub-suffix can sit between parent and query and mask the parent
// match. Walking every parent avoids that.
func (s *domainSection) matchReversed(parents []string) bool {
	if len(s.reversed) == 0 {
		return false
	}
	for _, rq := range parents {
		idx := sort.SearchStrings(s.reversed, rq)
		if idx < len(s.reversed) && s.reversed[idx] == rq {
			return true
		}
	}
	return false
}

// Match reports whether host hits any suffix rule in this section.
// Convenience wrapper over matchReversed — normalizes host via ReversedParents.
func (s *domainSection) Match(host string) bool {
	return s.matchReversed(ReversedParents(host))
}

// MatchDomain reports whether host should be routed by this set.
// Excludes take priority — a host matching ExcludeDomains is rejected
// even when it would otherwise hit DomainSuffixes.
// Convenience wrapper — the hot path uses MatchDomainReversed with
// parents computed once by ReversedParents.
func (s *NamedSet) MatchDomain(host string) bool {
	return s.MatchDomainReversed(ReversedParents(host))
}
