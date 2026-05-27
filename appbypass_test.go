package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// buildManifest picks up both legacy .k2b and current .krs files; both
// strip their extension to form the manifest key. The k2 client picks
// whichever format it knows how to read (key collisions across formats
// are allowed and expected — same region in both layouts).
func TestBuildManifest_IncludesKRSAndK2B(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "cn-direct.k2b"), []byte("K2RB-stub"), 0o644); err != nil {
		t.Fatalf("write k2b: %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, "cn.krs"), []byte("K2RL-stub"), 0o644); err != nil {
		t.Fatalf("write krs: %v", err)
	}
	// Non-bundle files must be ignored.
	if err := os.WriteFile(filepath.Join(out, "misc.yaml"), []byte("x: 1"), 0o644); err != nil {
		t.Fatalf("write misc: %v", err)
	}

	m := buildManifest(out)
	if _, ok := m.Bundles["cn-direct"]; !ok {
		t.Errorf("manifest missing cn-direct: %+v", m.Bundles)
	}
	if _, ok := m.Bundles["cn"]; !ok {
		t.Errorf("manifest missing cn (from cn.krs): %+v", m.Bundles)
	}
	for badKey := range map[string]struct{}{"misc.yaml": {}, "misc": {}} {
		if _, ok := m.Bundles[badKey]; ok {
			t.Errorf("manifest should not include %q: %+v", badKey, m.Bundles)
		}
	}
	// Manifest must serialize as valid JSON (CI publishes it).
	if _, err := json.Marshal(m); err != nil {
		t.Errorf("marshal manifest: %v", err)
	}
}
