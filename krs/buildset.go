package krs

import "bytes"

// BuildSet compiles s's write-input fields (DomainSuffixes, ExcludeDomains,
// CIDRs) into in-memory match state and returns it ready to use as a Matcher.
// Normalization is identical to WriteBundle→ReadBundle, so a directly-built
// set matches exactly as a file-loaded one.
//
// Intended for setup-time construction (e.g. compiling a few inline config
// rules), NOT the per-match hot path: it serializes + parses a one-set bundle.
func BuildSet(s NamedSet) (*NamedSet, error) {
	var buf bytes.Buffer
	if err := WriteBundle(&buf, &Bundle{Sets: []NamedSet{s}}); err != nil {
		return nil, err
	}
	b, err := ReadBundle(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return &b.Sets[0], nil
}

// IsEmpty reports whether the set has no positive match rules (domain
// suffixes or IP ranges). An exclude-only set is considered empty because
// excludes alone match nothing.
func (s *NamedSet) IsEmpty() bool {
	return len(s.domainSection.reversed) == 0 &&
		len(s.ipv4.starts) == 0 &&
		len(s.ipv6.starts) == 0
}
