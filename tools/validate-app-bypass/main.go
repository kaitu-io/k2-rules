// validate-app-bypass lints app-bypass-<region>.yaml files in this repo
// before the daily rule build ships them to CDN. Exits 1 on any violation
// so CI fails fast.
//
// Run from repo root:
//
//	go run ./tools/validate-app-bypass app-bypass/
//
// Schema source of truth: k2/appbypass + spec
//
//	docs/superpowers/specs/2026-05-25-app-bypass-engine-managed-design.md (§4, §11.2).
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
	supportedVersion = 1
	maxEntryLen      = 256
	maxEntriesPerSet = 500
)

type rawFile struct {
	Version     int        `yaml:"version"`
	Region      string     `yaml:"region"`
	Description string     `yaml:"description,omitempty"`
	Android     rawAndroid `yaml:"android,omitempty"`
	Desktop     rawDesktop `yaml:"desktop,omitempty"`
}

type rawAndroid struct {
	InstallerExact []string `yaml:"installer_exact,omitempty"`
	PackageExact   []string `yaml:"package_exact,omitempty"`
	PackagePrefix  []string `yaml:"package_prefix,omitempty"`
}

type rawDesktop struct {
	ProcessExact  []string `yaml:"process_exact,omitempty"`
	ProcessPrefix []string `yaml:"process_prefix,omitempty"`
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

	errs = append(errs, lintEntries("android.installer_exact", raw.Android.InstallerExact, lintExact)...)
	errs = append(errs, lintEntries("android.package_exact", raw.Android.PackageExact, lintExact)...)
	errs = append(errs, lintEntries("android.package_prefix", raw.Android.PackagePrefix, lintPackagePrefix)...)
	errs = append(errs, lintEntries("desktop.process_exact", raw.Desktop.ProcessExact, lintExact)...)
	errs = append(errs, lintEntries("desktop.process_prefix", raw.Desktop.ProcessPrefix, lintExact)...)

	errs = append(errs, lintCrossDuplicates("android.package_exact vs android.package_prefix",
		raw.Android.PackageExact, raw.Android.PackagePrefix, false)...)
	errs = append(errs, lintCrossDuplicates("desktop.process_exact vs desktop.process_prefix",
		raw.Desktop.ProcessExact, raw.Desktop.ProcessPrefix, true)...)

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
// duplicate detection. Returns one error per violation.
func lintEntries(setName string, entries []string, perEntry entryLinter) []error {
	if len(entries) > maxEntriesPerSet {
		return []error{fmt.Errorf("%s: %d entries exceeds cap %d", setName, len(entries), maxEntriesPerSet)}
	}
	var errs []error
	seen := make(map[string]int, len(entries))
	for i, e := range entries {
		trimmed := strings.TrimSpace(e)
		if trimmed != e {
			errs = append(errs, fmt.Errorf("%s[%d]: leading/trailing whitespace", setName, i))
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

func lintExact(s string) error {
	if strings.ContainsAny(s, " \t") {
		return errors.New("contains whitespace")
	}
	return nil
}

func lintPackagePrefix(s string) error {
	if err := lintExact(s); err != nil {
		return err
	}
	if !strings.HasSuffix(s, ".") {
		return errors.New("package_prefix must end with '.' to prevent boundary collisions (e.g. 'com.tencent' would match 'com.tencentX.foo')")
	}
	return nil
}

// lintCrossDuplicates flags entries that appear both in an exact set and
// the matching prefix set. caseInsensitive=true is appropriate for desktop
// where the matcher is case-insensitive; case-sensitive for android.
func lintCrossDuplicates(label string, exact, prefix []string, caseInsensitive bool) []error {
	if len(exact) == 0 || len(prefix) == 0 {
		return nil
	}
	norm := func(s string) string {
		if caseInsensitive {
			return strings.ToLower(s)
		}
		return s
	}
	exactSet := make(map[string]string, len(exact))
	for _, e := range exact {
		exactSet[norm(e)] = e
	}
	var errs []error
	for _, p := range prefix {
		key := norm(p)
		if orig, hit := exactSet[key]; hit {
			errs = append(errs, fmt.Errorf("%s: %q (prefix) duplicates %q (exact)", label, p, orig))
		}
	}
	return errs
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "validate-app-bypass: "+format+"\n", args...)
	os.Exit(1)
}
