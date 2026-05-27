package krs

import (
	"sort"
	"strings"
)

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
func (s *domainSection) Match(host string) bool {
	if len(s.reversed) == 0 || host == "" {
		return false
	}
	rq := reverseASCII(strings.ToLower(host))

	// Find the largest entry ≤ rq.
	idx := sort.SearchStrings(s.reversed, rq)
	// sort.SearchStrings returns the smallest i with s.reversed[i] ≥ rq.
	// We want the largest entry ≤ rq, which is at idx if it equals rq,
	// else idx-1.
	if idx < len(s.reversed) && s.reversed[idx] == rq {
		return true
	}
	if idx == 0 {
		return false
	}
	cand := s.reversed[idx-1]
	// Suffix match on label boundary: rq must equal cand or start with cand+"."
	if !strings.HasPrefix(rq, cand) {
		return false
	}
	return len(rq) == len(cand) || rq[len(cand)] == '.'
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
