package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPublishAppBypassPresets_Roundtrip verifies that the YAML at
// app-bypass/<region>.yaml lands in dist/ as app-bypass-<region>.yaml
// with byte-identical content, and that buildManifest picks it up with
// the full filename as the key.
func TestPublishAppBypassPresets_Roundtrip(t *testing.T) {
	src := t.TempDir()
	out := t.TempDir()

	body := []byte("version: 1\nregion: cn\n")
	if err := os.WriteFile(filepath.Join(src, "cn.yaml"), body, 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	// Files that shouldn't be copied: README, subdirs, non-yaml.
	if err := os.WriteFile(filepath.Join(src, "README.md"), []byte("doc"), 0644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	if err := os.Mkdir(filepath.Join(src, "subdir"), 0755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	if err := publishAppBypassPresets(src, out); err != nil {
		t.Fatalf("publish: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(out, "app-bypass-cn.yaml"))
	if err != nil {
		t.Fatalf("read published: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("content drift:\n got=%q\nwant=%q", got, body)
	}

	// README + subdir must not appear in dist.
	entries, _ := os.ReadDir(out)
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".md") || e.IsDir() {
			t.Errorf("unexpected dist entry: %s", name)
		}
	}
}

// TestPublishAppBypassPresets_MissingDir is non-fatal — main.go should
// still ship .k2b bundles even if the app-bypass directory was removed.
func TestPublishAppBypassPresets_MissingDir(t *testing.T) {
	out := t.TempDir()
	if err := publishAppBypassPresets(filepath.Join(t.TempDir(), "does-not-exist"), out); err != nil {
		t.Fatalf("expected nil for missing dir, got %v", err)
	}
}

// TestBuildManifest_IncludesAppBypassYaml verifies the manifest carries
// the YAML preset alongside .k2b bundles with the full filename as the
// key (engine-side appbypass.Load matches by glob, not by stripped key).
func TestBuildManifest_IncludesAppBypassYaml(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "cn-direct.k2b"), []byte("K2RB-stub"), 0644); err != nil {
		t.Fatalf("write k2b: %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, "app-bypass-cn.yaml"), []byte("version: 1\nregion: cn\n"), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	// Top-level non-app-bypass yaml is ignored (only app-bypass-*.yaml).
	if err := os.WriteFile(filepath.Join(out, "misc.yaml"), []byte("x: 1"), 0644); err != nil {
		t.Fatalf("write misc: %v", err)
	}

	m := buildManifest(out)
	if _, ok := m.Bundles["cn-direct"]; !ok {
		t.Errorf("manifest missing cn-direct: %+v", m.Bundles)
	}
	if _, ok := m.Bundles["app-bypass-cn.yaml"]; !ok {
		t.Errorf("manifest missing app-bypass-cn.yaml: %+v", m.Bundles)
	}
	if _, ok := m.Bundles["misc.yaml"]; ok {
		t.Errorf("manifest should not include misc.yaml: %+v", m.Bundles)
	}
	if _, ok := m.Bundles["misc"]; ok {
		t.Errorf("manifest should not include misc: %+v", m.Bundles)
	}
	// Sanity: manifest must serialize as valid JSON (CI publishes it).
	if _, err := json.Marshal(m); err != nil {
		t.Errorf("marshal manifest: %v", err)
	}
}
