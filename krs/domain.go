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
//
// Algorithm: walk host's parent suffixes (host, then host with the
// leftmost label stripped, repeat) and exact-match each against the
// reversed table. A single binary search "largest entry ≤ rq" is unsafe
// when the table contains both a parent and a descendant suffix in the
// same set — a lex-smaller sibling sub-suffix can sit between parent
// and query and mask the parent match.
func (s *domainSection) Match(host string) bool {
	if len(s.reversed) == 0 || host == "" {
		return false
	}
	h := strings.ToLower(host)
	// Tolerate FQDN trailing dot (real DNS responses surface "weibo.com."
	// shape) so callers don't have to normalize.
	if len(h) > 0 && h[len(h)-1] == '.' {
		h = h[:len(h)-1]
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
