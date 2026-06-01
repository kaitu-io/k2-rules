package krs

import (
	"net/netip"
	"strings"
)

// MatchableApp is the input to MatchInstalled. The k2 daemon converts
// its provider.InstalledApp into MatchableApp at the call site so this
// package stays free of provider imports.
type MatchableApp struct {
	ID                   string   // android: packageName; desktop: app identity
	Label                string   // human-readable name (passed through unchanged)
	InstallerPackageName string   // android only
	ProcessNames         []string // desktop: basenames; not pre-lowercased
}

// MatchedEntry is one hit returned by MatchInstalled.
//
// HitKind is one of:
//   - "installer" — InstallerPackageName matched AndroidPatterns.Installers
//   - "app"       — ID (Android) or a ProcessName (desktop) matched a glob
type MatchedEntry struct {
	ID         string
	Label      string
	Names      []string // the input names that matched (for desktop: the matching process names)
	HitKind    string
	HitPattern string
}

// MatchAndroidInstaller does an exact-match lookup against Android.Installers.
// Returns the matched pattern (== query) and true on hit.
func (p *AppPatterns) MatchAndroidInstaller(installerPkg string) (string, bool) {
	if p == nil || installerPkg == "" {
		return "", false
	}
	for _, x := range p.Android.Installers {
		if x == installerPkg {
			return x, true
		}
	}
	return "", false
}

// MatchAndroidPackage applies single-* glob over Android.Apps (case-sensitive).
func (p *AppPatterns) MatchAndroidPackage(pkg string) (string, bool) {
	if p == nil {
		return "", false
	}
	return firstGlobHit(p.Android.Apps, pkg)
}

// MatchWindowsProcess matches against Windows.Apps. Patterns are stored
// lowercased; the query is lowercased here.
func (p *AppPatterns) MatchWindowsProcess(name string) (string, bool) {
	if p == nil {
		return "", false
	}
	return firstGlobHit(p.Windows.Apps, strings.ToLower(name))
}

// MatchDarwinProcess matches against Darwin.Apps (case-sensitive).
func (p *AppPatterns) MatchDarwinProcess(name string) (string, bool) {
	if p == nil {
		return "", false
	}
	return firstGlobHit(p.Darwin.Apps, name)
}

// firstGlobHit returns the first pattern in patterns matching input.
func firstGlobHit(patterns []string, input string) (string, bool) {
	for _, pat := range patterns {
		if matchGlob(pat, input) {
			return pat, true
		}
	}
	return "", false
}

// MatchInstalled runs apps through patterns, returning one MatchedEntry per
// app that hits. Priority within one app (first-hit wins):
//
//	android: installer > apps glob
//	desktop: apps glob over each ProcessName
//
// goos selects which subset is relevant:
//
//	"android"             → only Android patterns
//	"darwin"              → only Darwin patterns
//	"windows"             → only Windows patterns
//	"linux", anything else → no match (no Linux patterns yet)
func MatchInstalled(p *AppPatterns, apps []MatchableApp, goos string) []MatchedEntry {
	if p == nil || len(apps) == 0 {
		return nil
	}
	out := make([]MatchedEntry, 0, len(apps))
	for _, a := range apps {
		hit, names := matchOneInstalled(p, a, goos)
		if hit.HitKind == "" {
			continue
		}
		hit.ID = a.ID
		hit.Label = a.Label
		hit.Names = names
		out = append(out, hit)
	}
	return out
}

func matchOneInstalled(p *AppPatterns, a MatchableApp, goos string) (MatchedEntry, []string) {
	switch goos {
	case "android":
		if pat, ok := p.MatchAndroidInstaller(a.InstallerPackageName); ok {
			return MatchedEntry{HitKind: "installer", HitPattern: pat}, []string{a.ID}
		}
		if pat, ok := p.MatchAndroidPackage(a.ID); ok {
			return MatchedEntry{HitKind: "app", HitPattern: pat}, []string{a.ID}
		}
	case "windows":
		if pat, names, ok := firstProcessHit(a.ProcessNames, p.MatchWindowsProcess); ok {
			return MatchedEntry{HitKind: "app", HitPattern: pat}, names
		}
	case "darwin":
		if pat, names, ok := firstProcessHit(a.ProcessNames, p.MatchDarwinProcess); ok {
			return MatchedEntry{HitKind: "app", HitPattern: pat}, names
		}
	}
	return MatchedEntry{}, nil
}

// firstProcessHit walks names and returns the first that matches via match.
// All names that match the chosen pattern are returned (preview UX surfaces
// every alias hit so users can see why an app was selected).
func firstProcessHit(names []string, match func(string) (string, bool)) (string, []string, bool) {
	for _, n := range names {
		if pat, ok := match(n); ok {
			// Collect all aliases that match THIS pattern (not just the first one).
			var aliases []string
			for _, m := range names {
				if matched, _ := match(m); matched == pat {
					aliases = append(aliases, m)
				}
			}
			return pat, aliases, true
		}
	}
	return "", nil, false
}

// Matcher is the per-set routing-match surface shared by the heap reader
// (*NamedSet) and the mmap reader (*diskSet, added in a later task). Domain
// matching takes pre-reversed parent suffixes (ReversedParents) so the
// consumer normalizes once per lookup, not once per set.
type Matcher interface {
	MatchDomainReversed(reversedParents []string) bool
	MatchIP(addr netip.Addr) bool
}

// MatchDomainReversed reports whether the pre-reversed parent list (computed
// by ReversedParents) hits this set. Excludes take priority over suffixes.
func (s *NamedSet) MatchDomainReversed(reversedParents []string) bool {
	if s.excludeSection.matchReversed(reversedParents) {
		return false
	}
	return s.domainSection.matchReversed(reversedParents)
}

// Compile-time assertion: *NamedSet satisfies Matcher.
var _ Matcher = (*NamedSet)(nil)
