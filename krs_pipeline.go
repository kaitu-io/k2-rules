package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kaitu-io/k2-rules/krs"
	"gopkg.in/yaml.v3"
)

// appBypassYAMLv2 mirrors the on-disk schema in app-bypass/<region>.yaml.
// Authoritative validation lives in tools/validate-app-bypass; this struct
// is the lenient pipeline parse used after validator has already run.
type appBypassYAMLv2 struct {
	Version int `yaml:"version"`
	Region  string
	Android struct {
		Installers []string `yaml:"installers"`
		Apps       []string `yaml:"apps"`
	} `yaml:"android"`
	Windows struct {
		Apps []string `yaml:"apps"`
	} `yaml:"windows"`
	Darwin struct {
		Apps []string `yaml:"apps"`
	} `yaml:"darwin"`
}

// loadAppBypassYAML reads a v2 app-bypass YAML and returns the corresponding
// AppPatterns. A missing file is non-fatal (returns nil, nil) — region
// bundles without an app-bypass YAML produce a pure-routing .krs.
func loadAppBypassYAML(path string) (*krs.AppPatterns, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var raw appBypassYAMLv2
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("yaml decode %s: %w", path, err)
	}
	if raw.Version != 2 {
		return nil, fmt.Errorf("%s: unsupported version %d (want 2)", path, raw.Version)
	}
	// Pipeline-side region check (validator tool enforces the same at PR
	// time, but a renamed-or-hand-edited file would otherwise silently
	// ship the wrong region's bypass list — high-blast-radius misrouting).
	expectRegion := strings.TrimSuffix(filepath.Base(path), ".yaml")
	if raw.Region != expectRegion {
		return nil, fmt.Errorf("%s: region %q must match filename %q",
			path, raw.Region, expectRegion)
	}
	apps := &krs.AppPatterns{
		Android: krs.AndroidPatterns{
			Installers: raw.Android.Installers,
			Apps:       raw.Android.Apps,
		},
		Windows: krs.WindowsPatterns{Apps: raw.Windows.Apps},
		Darwin:  krs.DarwinPatterns{Apps: raw.Darwin.Apps},
	}
	if isEmptyAppPatterns(apps) {
		return nil, nil
	}
	return apps, nil
}

func isEmptyAppPatterns(p *krs.AppPatterns) bool {
	return len(p.Android.Installers) == 0 &&
		len(p.Android.Apps) == 0 &&
		len(p.Windows.Apps) == 0 &&
		len(p.Darwin.Apps) == 0
}

// bundleSetsToKRS lifts the pipeline-internal bundleSet (Domains/CIDRs as
// raw input strings) into krs.NamedSet (which expects the same field names
// shape). Field rename: Domains → DomainSuffixes (krs makes the suffix
// semantics explicit at the type level).
func bundleSetsToKRS(in []bundleSet) []krs.NamedSet {
	out := make([]krs.NamedSet, len(in))
	for i, s := range in {
		out[i] = krs.NamedSet{
			Name:           s.Name,
			DomainSuffixes: s.Domains,
			ExcludeDomains: s.ExcludeDomains,
			CIDRs:          s.CIDRs,
		}
	}
	return out
}

// writeKRSBundle serializes sets + apps as one .krs file at path.
func writeKRSBundle(path string, sets []bundleSet, apps *krs.AppPatterns) error {
	bundle := &krs.Bundle{
		Sets: bundleSetsToKRS(sets),
		Apps: apps,
	}
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, bundle); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return nil
}
