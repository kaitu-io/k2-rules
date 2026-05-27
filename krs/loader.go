package krs

import (
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Load reads every *.krs file in cacheDir and returns the parsed bundles.
//
// A missing cacheDir is non-fatal — returns nil, nil. Corrupt or unreadable
// bundles are skipped with a warning log; the surviving bundles are still
// returned. This matches k2's existing rule.Load behavior so the client
// can boot with partial rule data when one bundle is bad.
func Load(cacheDir string) ([]*Bundle, error) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var bundles []*Bundle
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".krs") {
			continue
		}
		path := filepath.Join(cacheDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("krs: skip bundle (read failed)", "file", name, "err", err)
			continue
		}
		b, err := ReadBundle(data)
		if err != nil {
			slog.Warn("krs: skip bundle (parse failed)", "file", name, "err", err)
			continue
		}
		bundles = append(bundles, b)
	}
	return bundles, nil
}

// Index builds a name→*NamedSet lookup across all bundles.
// On name collision, later bundles overwrite earlier ones (last wins) —
// matches k2's existing rule.Index contract. Collisions emit a warn:
// the behavior is intentional, but a silent overwrite would mask a
// curation mistake (two bundles defining the same set name) that makes
// runtime routing Load-order-dependent.
func Index(bundles []*Bundle) map[string]*NamedSet {
	idx := make(map[string]*NamedSet)
	for _, b := range bundles {
		for i := range b.Sets {
			name := b.Sets[i].Name
			if _, dup := idx[name]; dup {
				slog.Warn("krs: set name collision across bundles — last bundle wins",
					"set", name)
			}
			idx[name] = &b.Sets[i]
		}
	}
	return idx
}
