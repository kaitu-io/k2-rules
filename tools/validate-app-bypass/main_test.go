package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeYAML(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidate_V2_Valid(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "cn.yaml", `
version: 2
region: cn
description: |
  China region preset.
android:
  installers:
    - com.xiaomi.market
  apps:
    - "com.tencent.*"
    - "com.alipay.*"
windows:
  apps:
    - "WeChat*"
darwin:
  apps:
    - "WeChat"
    - "WeChatHelper*"
`)
	if errs := validateFile(path); len(errs) > 0 {
		t.Fatalf("expected clean, got: %v", errs)
	}
}

func TestValidate_V2_RejectsV1Fields(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "cn.yaml", `
version: 1
region: cn
android:
  installer_exact:
    - com.xiaomi.market
desktop:
  process_prefix:
    - WeChat
`)
	errs := validateFile(path)
	if len(errs) == 0 {
		t.Fatal("expected errors for v1 schema")
	}
}

func TestValidate_V2_RegionMustMatchFilename(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "cn.yaml", `
version: 2
region: ir
android:
  installers: [com.x]
`)
	errs := validateFile(path)
	if !hasErr(errs, "region") {
		t.Errorf("expected region mismatch error, got: %v", errs)
	}
}

func TestValidate_V2_RejectsEmptyAndWhitespace(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "cn.yaml", `
version: 2
region: cn
android:
  apps:
    - ""
    - "  "
    - "  com.foo  "
`)
	errs := validateFile(path)
	if len(errs) < 2 {
		t.Errorf("expected multiple errors, got %d: %v", len(errs), errs)
	}
}

func TestValidate_V2_RejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "cn.yaml", `
version: 2
region: cn
android:
  apps:
    - "com.foo.*"
    - "com.foo.*"
`)
	errs := validateFile(path)
	if !hasErr(errs, "duplicate") {
		t.Errorf("expected duplicate error, got: %v", errs)
	}
}

func TestValidate_V2_InstallersAreExact_RejectsGlob(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "cn.yaml", `
version: 2
region: cn
android:
  installers:
    - "com.xiaomi.*"
`)
	errs := validateFile(path)
	if !hasErr(errs, "installers") {
		t.Errorf("expected installer-glob error, got: %v", errs)
	}
}

// All-star patterns (*, **, ***, …) collapse to "match everything" under
// matchGlob and would route every installed app direct — the canonical
// accidental-wildcard attack vector. The validator must reject every form,
// not just the bare single-* it originally guarded against.
func TestValidate_V2_RejectsAllStarPatterns(t *testing.T) {
	for _, pat := range []string{"*", "**", "***", "*****"} {
		dir := t.TempDir()
		path := writeYAML(t, dir, "cn.yaml", `
version: 2
region: cn
android:
  apps:
    - "`+pat+`"
`)
		errs := validateFile(path)
		if !hasErr(errs, "wildcard") && !hasErr(errs, "*") {
			t.Errorf("pattern %q: expected wildcard rejection, got: %v", pat, errs)
		}
	}
}

func TestValidate_V2_UnknownFieldsRejected(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, "cn.yaml", `
version: 2
region: cn
android:
  installers: [com.x]
ios:
  apps: ["com.example"]
`)
	errs := validateFile(path)
	if len(errs) == 0 {
		t.Errorf("expected unknown-field error for 'ios:' at top level")
	}
}

func hasErr(errs []error, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), substr) {
			return true
		}
	}
	return false
}
