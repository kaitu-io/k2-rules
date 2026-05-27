package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaitu-io/k2-rules/krs"
)

func TestLoadAppBypassYAML_V2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cn.yaml")
	body := `
version: 2
region: cn
android:
  installers:
    - com.xiaomi.market
  apps:
    - "com.tencent.*"
windows:
  apps:
    - "WeChat*"
darwin:
  apps:
    - "WeChat*"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	apps, err := loadAppBypassYAML(path)
	if err != nil {
		t.Fatalf("loadAppBypassYAML: %v", err)
	}
	if apps == nil {
		t.Fatal("apps nil")
	}
	if len(apps.Android.Installers) != 1 || apps.Android.Installers[0] != "com.xiaomi.market" {
		t.Errorf("installers: %+v", apps.Android.Installers)
	}
	if len(apps.Android.Apps) != 1 || apps.Android.Apps[0] != "com.tencent.*" {
		t.Errorf("android.apps: %+v", apps.Android.Apps)
	}
	if len(apps.Windows.Apps) != 1 || apps.Windows.Apps[0] != "WeChat*" {
		t.Errorf("windows.apps: %+v", apps.Windows.Apps)
	}
	if len(apps.Darwin.Apps) != 1 {
		t.Errorf("darwin.apps: %+v", apps.Darwin.Apps)
	}
}

// YAML region field must match the filename region. The validator tool
// already enforces this at PR time, but the pipeline trusts whatever lands
// on disk and would silently ship ir.yaml's bypass list inside cn.krs if
// someone renamed the file or hand-edited region. Double-check at load
// time so a misnamed file fails the build instead of misrouting users.
func TestLoadAppBypassYAML_RejectsRegionMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cn.yaml") // filename says cn
	body := `
version: 2
region: ir
android:
  installers:
    - com.farsitel.bazaar
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadAppBypassYAML(path)
	if err == nil {
		t.Fatal("expected region-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "region") {
		t.Errorf("expected error to mention 'region', got: %v", err)
	}
}

func TestLoadAppBypassYAML_MissingFileReturnsNil(t *testing.T) {
	apps, err := loadAppBypassYAML(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	if apps != nil {
		t.Errorf("expected nil apps, got %+v", apps)
	}
}

func TestBundleSetsToKRS_Preserves(t *testing.T) {
	in := []bundleSet{
		{
			Name:           "google",
			Domains:        []string{"google.com", "google.cn"},
			ExcludeDomains: []string{"hk.google.com"},
			CIDRs:          []string{"8.8.8.0/24"},
		},
	}
	out := bundleSetsToKRS(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 set, got %d", len(out))
	}
	if out[0].Name != "google" {
		t.Errorf("name: %q", out[0].Name)
	}
	if len(out[0].DomainSuffixes) != 2 {
		t.Errorf("domains: %+v", out[0].DomainSuffixes)
	}
	if len(out[0].ExcludeDomains) != 1 {
		t.Errorf("excludes: %+v", out[0].ExcludeDomains)
	}
	if len(out[0].CIDRs) != 1 {
		t.Errorf("cidrs: %+v", out[0].CIDRs)
	}
}

// Smoke test against the real shipping YAMLs — guards against future
// schema drift between the YAMLs and the pipeline parser.
func TestLoadAppBypassYAML_RealRepoFixtures(t *testing.T) {
	for _, region := range []string{"cn", "ir"} {
		apps, err := loadAppBypassYAML(filepath.Join("app-bypass", region+".yaml"))
		if err != nil {
			t.Errorf("region %s: %v", region, err)
			continue
		}
		if apps == nil {
			t.Errorf("region %s: nil AppPatterns (file empty?)", region)
			continue
		}
		if len(apps.Android.Installers) == 0 {
			t.Errorf("region %s: no Android installers", region)
		}
	}
}

func TestWriteKRSBundle_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cn.krs")
	sets := []bundleSet{{Name: "google", Domains: []string{"google.com"}}}
	apps := &krs.AppPatterns{
		Android: krs.AndroidPatterns{Installers: []string{"com.xiaomi.market"}},
	}
	if err := writeKRSBundle(path, sets, apps); err != nil {
		t.Fatalf("writeKRSBundle: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := krs.ReadBundle(data)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	if len(got.Sets) != 1 || got.Sets[0].Name != "google" {
		t.Errorf("Sets: %+v", got.Sets)
	}
	if got.Apps == nil || len(got.Apps.Android.Installers) != 1 {
		t.Errorf("Apps: %+v", got.Apps)
	}
	if !bytes.Equal(data[0:4], []byte("K2RL")) {
		t.Errorf("magic: %x", data[0:4])
	}
}
