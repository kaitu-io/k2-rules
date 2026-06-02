package krs

// RuleCount returns the number of positive match rules across all sets:
// domain suffixes plus IP ranges (v4 + v6). Exclude domains are not counted —
// like IsEmpty, excludes alone match nothing. Used by publish-time validation
// and the manifest to detect empty or regressed bundles. Operates on
// reader-populated internal state, so call after ReadBundle (or on a bundle
// whose write-input slices were consumed by WriteBundle).
func (b *Bundle) RuleCount() int {
	n := 0
	for i := range b.Sets {
		s := &b.Sets[i]
		n += len(s.domainSection.reversed)
		n += len(s.ipv4.starts)
		n += len(s.ipv6.starts)
	}
	return n
}
