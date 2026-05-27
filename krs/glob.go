package krs

import "strings"

// matchGlob reports whether input matches pattern under single-* semantics:
//   - `*` matches zero or more arbitrary characters (no path semantics)
//   - no `?`, `[...]`, or brace expansion
//   - empty pattern matches only empty input
//   - case handling is the caller's responsibility (Windows pre-lowercases
//     both pattern and query elsewhere; Android/Darwin compare verbatim)
//
// Algorithm: split on `*`. The first segment must anchor at start (unless
// pattern begins with `*`); the last must anchor at end. Middle segments
// must appear in order. Linear time in len(pattern)+len(input).
func matchGlob(pattern, input string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == input
	}

	// Anchor the head.
	if !strings.HasPrefix(input, parts[0]) {
		return false
	}
	input = input[len(parts[0]):]

	// Anchor the tail.
	last := parts[len(parts)-1]
	if !strings.HasSuffix(input, last) {
		return false
	}
	input = input[:len(input)-len(last)]

	// Middle segments must appear in order, non-overlapping.
	for _, seg := range parts[1 : len(parts)-1] {
		if seg == "" {
			continue
		}
		i := strings.Index(input, seg)
		if i < 0 {
			return false
		}
		input = input[i+len(seg):]
	}
	return true
}
