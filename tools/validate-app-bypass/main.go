// validate-app-bypass lints app-bypass/<region>.yaml files before they are
// compiled into .krs bundles. Exits 1 on any violation so CI fails fast.
//
// Run from repo root:
//
//	go run ./tools/validate-app-bypass app-bypass/
//
// Schema is v2 — see app-bypass/README.md for field meanings.
// The v2 YAML is the compile source for app sections inside .krs bundles
// (see github.com/kaitu-io/k2-rules/krs for the wire format).
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	supportedVersion = 2
	maxEntryLen      = 256
	maxEntriesPerSet = 500
)

type rawFile struct {
	Version     int        `yaml:"version"`
	Region      string     `yaml:"region"`
	Description string     `yaml:"description,omitempty"`
	Android     rawAndroid `yaml:"android,omitempty"`
	Windows     rawWindows `yaml:"windows,omitempty"`
	Darwin      rawDarwin  `yaml:"darwin,omitempty"`
}

type rawAndroid struct {
	Installers []string `yaml:"installers,omitempty"` // exact-match
	Apps       []string `yaml:"apps,omitempty"`       // glob, case-sensitive
}

type rawWindows struct {
	Apps []string `yaml:"apps,omitempty"` // glob, case-insensitive
}

type rawDarwin struct {
	Apps []string `yaml:"apps,omitempty"` // glob, case-sensitive
}

func main() {
	flag.Parse()
	dir := flag.Arg(0)
	if dir == "" {
		dir = "app-bypass"
	}
	info, err := os.Stat(dir)
	if err != nil {
		fail("cannot stat %s: %v", dir, err)
	}
	if !info.IsDir() {
		fail("%s is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		fail("read %s: %v", dir, err)
	}

	yamlFiles := 0
	violations := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		yamlFiles++
		path := filepath.Join(dir, name)
		if errs := validateFile(path); len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "FAIL %s\n", path)
			for _, err := range errs {
				fmt.Fprintf(os.Stderr, "  - %v\n", err)
			}
			violations += len(errs)
			continue
		}
		fmt.Printf("OK   %s\n", path)
	}
	if yamlFiles == 0 {
		fail("no *.yaml files in %s", dir)
	}
	if violations > 0 {
		fail("%d violation(s) across %d file(s)", violations, yamlFiles)
	}
	fmt.Printf("validate-app-bypass: %d file(s) clean\n", yamlFiles)
}

func validateFile(path string) []error {
	data, err := os.ReadFile(path)
	if err != nil {
		return []error{fmt.Errorf("read: %w", err)}
	}
	raw, perr := parseStrict(data)
	if perr != nil {
		return []error{perr}
	}

	var errs []error

	if raw.Version != supportedVersion {
		errs = append(errs, fmt.Errorf("version must be %d, got %d", supportedVersion, raw.Version))
	}

	expectRegion := strings.TrimSuffix(filepath.Base(path), ".yaml")
	if raw.Region != expectRegion {
		errs = append(errs, fmt.Errorf("region %q must match filename %q", raw.Region, expectRegion))
	}

	errs = append(errs, lintEntries("android.installers", raw.Android.Installers, lintExactNoGlob)...)
	errs = append(errs, lintEntries("android.apps", raw.Android.Apps, lintGlob)...)
	errs = append(errs, lintEntries("windows.apps", raw.Windows.Apps, lintGlob)...)
	errs = append(errs, lintEntries("darwin.apps", raw.Darwin.Apps, lintGlob)...)

	return errs
}

func parseStrict(data []byte) (*rawFile, error) {
	var raw rawFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("yaml decode: %w", err)
	}
	return &raw, nil
}

type entryLinter func(string) error

// lintEntries enforces per-set caps + per-entry constraints + intra-set
// duplicate detection. Whitespace and empty entries flagged as separate errors.
func lintEntries(setName string, entries []string, perEntry entryLinter) []error {
	if len(entries) > maxEntriesPerSet {
		return []error{fmt.Errorf("%s: %d entries exceeds cap %d", setName, len(entries), maxEntriesPerSet)}
	}
	var errs []error
	seen := make(map[string]int, len(entries))
	for i, e := range entries {
		trimmed := strings.TrimSpace(e)
		if trimmed != e {
			errs = append(errs, fmt.Errorf("%s[%d]: leading/trailing whitespace in %q", setName, i, e))
		}
		if trimmed == "" {
			errs = append(errs, fmt.Errorf("%s[%d]: empty entry", setName, i))
			continue
		}
		if len(trimmed) > maxEntryLen {
			errs = append(errs, fmt.Errorf("%s[%d]: entry length %d exceeds cap %d",
				setName, i, len(trimmed), maxEntryLen))
		}
		if prev, dup := seen[trimmed]; dup {
			errs = append(errs, fmt.Errorf("%s[%d]: duplicate of [%d] %q", setName, i, prev, trimmed))
			continue
		}
		seen[trimmed] = i
		if perEntry != nil {
			if err := perEntry(trimmed); err != nil {
				errs = append(errs, fmt.Errorf("%s[%d] %q: %w", setName, i, trimmed, err))
			}
		}
	}
	return errs
}

// lintExactNoGlob: Android installers are exact-match identifiers — no `*`.
func lintExactNoGlob(s string) error {
	if strings.ContainsRune(s, '*') {
		return errors.New("installers must be exact-match (no '*' allowed)")
	}
	if strings.ContainsAny(s, " \t") {
		return errors.New("contains whitespace")
	}
	return nil
}

// lintGlob: app patterns support single-* glob. Empty/all-`*` patterns are
// already rejected upstream (empty → trimmed empty; "*" alone matches
// everything which is almost certainly a maintainer error).
func lintGlob(s string) error {
	if s == "*" {
		return errors.New("pattern '*' matches everything — reject as accidental wildcard")
	}
	if strings.ContainsAny(s, " \t") {
		return errors.New("contains whitespace")
	}
	return nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "validate-app-bypass: "+format+"\n", args...)
	os.Exit(1)
}
