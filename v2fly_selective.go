package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// v2flyRule is one domain rule from a v2fly data file, with the attributes it
// carries (without the leading '@').
type v2flyRule struct {
	Domain string
	Attrs  map[string]bool
}

// resolveV2flySelective resolves an include spec — "name [@attr | @-attr]..." —
// against the v2fly data directory, honouring v2fly's selective inclusion:
// `include:list @a @-b` adds only the rules of `list` that carry @a and do not
// carry @b. The spec itself is read exactly like an include line, so
// "category-ads-all @ads" yields every rule in that tree tagged @ads.
//
// parseV2flyRecursive ignores include filters and pulls the whole included
// file. That over-inclusion is harmless for a direct/proxy route and fatal for
// a reject route (`include:google @ads` would block all of google), so sets
// that are rejected by the client must use this resolver.
//
// A missing or cyclic include is an error, never a silent skip: the caller
// decides whether a broken source fails the build.
func resolveV2flySelective(dataDir, spec string) ([]string, error) {
	name, want, unwant := parseIncludeSpec(spec)
	if name == "" {
		return nil, fmt.Errorf("empty v2fly spec %q", spec)
	}
	r := &v2flyResolver{dataDir: dataDir, cache: map[string][]v2flyRule{}}
	rules, err := r.resolve(name, nil)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var out []string
	for _, rule := range filterV2flyRules(rules, want, unwant) {
		if !seen[rule.Domain] {
			seen[rule.Domain] = true
			out = append(out, rule.Domain)
		}
	}
	return out, nil
}

// parseIncludeSpec splits "name @a @-b" into the list name and its filters.
func parseIncludeSpec(spec string) (name string, want, unwant []string) {
	fields := strings.Fields(spec)
	if len(fields) == 0 {
		return "", nil, nil
	}
	for _, f := range fields[1:] {
		switch {
		case strings.HasPrefix(f, "@-"):
			unwant = append(unwant, f[2:])
		case strings.HasPrefix(f, "@"):
			want = append(want, f[1:])
		}
	}
	return fields[0], want, unwant
}

func filterV2flyRules(rules []v2flyRule, want, unwant []string) []v2flyRule {
	if len(want) == 0 && len(unwant) == 0 {
		return rules
	}
	var out []v2flyRule
next:
	for _, rule := range rules {
		for _, a := range want {
			if !rule.Attrs[a] {
				continue next
			}
		}
		for _, a := range unwant {
			if rule.Attrs[a] {
				continue next
			}
		}
		out = append(out, rule)
	}
	return out
}

type v2flyResolver struct {
	dataDir string
	cache   map[string][]v2flyRule
}

// resolve returns the fully flattened rules of one data file. stack is the
// chain of files currently being resolved, for cycle detection.
func (r *v2flyResolver) resolve(name string, stack []string) ([]v2flyRule, error) {
	if rules, ok := r.cache[name]; ok {
		return rules, nil
	}
	for _, s := range stack {
		if s == name {
			return nil, fmt.Errorf("v2fly include cycle: %s -> %s", strings.Join(stack, " -> "), name)
		}
	}
	stack = append(stack, name)

	f, err := os.Open(filepath.Join(r.dataDir, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []v2flyRule
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		head := fields[0]

		if strings.HasPrefix(head, "include:") {
			incName, want, unwant := parseIncludeSpec(strings.TrimPrefix(strings.Join(fields, " "), "include:"))
			sub, err := r.resolve(incName, stack)
			if err != nil {
				return nil, fmt.Errorf("%s: include %s: %w", name, incName, err)
			}
			rules = append(rules, filterV2flyRules(sub, want, unwant)...)
			continue
		}
		if strings.HasPrefix(head, "regexp:") || strings.HasPrefix(head, "keyword:") {
			continue
		}
		domain := strings.TrimPrefix(strings.TrimPrefix(head, "domain:"), "full:")
		if domain == "" {
			continue
		}
		attrs := make(map[string]bool)
		for _, f := range fields[1:] {
			// '&' affiliations are data-management markers, not attributes.
			if strings.HasPrefix(f, "@") {
				attrs[f[1:]] = true
			}
		}
		rules = append(rules, v2flyRule{Domain: strings.ToLower(domain), Attrs: attrs})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	r.cache[name] = rules
	return rules, nil
}
