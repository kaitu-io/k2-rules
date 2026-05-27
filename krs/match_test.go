package krs_test

import (
	"bytes"
	"testing"

	"github.com/kaitu-io/k2-rules/krs"
)

// AppPatterns.MatchAndroidInstaller is exact-match (no glob).
func TestAppPatterns_MatchAndroidInstaller(t *testing.T) {
	apps := roundTripApps(t, &krs.AppPatterns{
		Android: krs.AndroidPatterns{Installers: []string{"com.xiaomi.market"}},
	})
	if pat, ok := apps.MatchAndroidInstaller("com.xiaomi.market"); !ok || pat != "com.xiaomi.market" {
		t.Errorf("exact hit: ok=%v pat=%q", ok, pat)
	}
	if _, ok := apps.MatchAndroidInstaller("com.xiaomi.market.foo"); ok {
		t.Error("installer is exact match, prefix should not hit")
	}
	if _, ok := apps.MatchAndroidInstaller(""); ok {
		t.Error("empty input should not match")
	}
}

// AppPatterns.MatchAndroidPackage applies glob semantics, case-sensitive.
func TestAppPatterns_MatchAndroidPackage(t *testing.T) {
	apps := roundTripApps(t, &krs.AppPatterns{
		Android: krs.AndroidPatterns{Apps: []string{"com.tencent.*", "com.alipay.*"}},
	})
	if pat, ok := apps.MatchAndroidPackage("com.tencent.mm"); !ok || pat != "com.tencent.*" {
		t.Errorf("glob hit: ok=%v pat=%q", ok, pat)
	}
	if _, ok := apps.MatchAndroidPackage("org.tencent.fake"); ok {
		t.Error("non-prefix should not hit")
	}
}

// Windows matching is case-insensitive: writer lowercases patterns,
// matcher must lowercase the query.
func TestAppPatterns_MatchWindowsProcess_CaseInsensitive(t *testing.T) {
	apps := roundTripApps(t, &krs.AppPatterns{
		Windows: krs.WindowsPatterns{Apps: []string{"WeChat*"}},
	})
	for _, q := range []string{"wechat.exe", "WeChat.exe", "WECHAT.EXE", "WeChatHelper"} {
		if _, ok := apps.MatchWindowsProcess(q); !ok {
			t.Errorf("MatchWindowsProcess(%q): want true", q)
		}
	}
	if _, ok := apps.MatchWindowsProcess("Notepad.exe"); ok {
		t.Error("MatchWindowsProcess(Notepad.exe): want false")
	}
}

// Darwin matching is case-sensitive.
func TestAppPatterns_MatchDarwinProcess_CaseSensitive(t *testing.T) {
	apps := roundTripApps(t, &krs.AppPatterns{
		Darwin: krs.DarwinPatterns{Apps: []string{"WeChat*"}},
	})
	if _, ok := apps.MatchDarwinProcess("WeChat"); !ok {
		t.Error("MatchDarwinProcess(WeChat): want true")
	}
	if _, ok := apps.MatchDarwinProcess("wechat"); ok {
		t.Error("MatchDarwinProcess(wechat): want false (case-sensitive)")
	}
}

// nil receiver and absent platforms return ok=false, no panic.
func TestAppPatterns_NilSafe(t *testing.T) {
	var p *krs.AppPatterns
	if _, ok := p.MatchAndroidPackage("x"); ok {
		t.Error("nil receiver should return false")
	}
}

// MatchInstalled per-platform routing — Android uses installer + apps,
// desktop platforms use apps only. goos selects which subset runs.
func TestMatchInstalled_AndroidPriority(t *testing.T) {
	apps := roundTripApps(t, &krs.AppPatterns{
		Android: krs.AndroidPatterns{
			Installers: []string{"com.xiaomi.market"},
			Apps:       []string{"com.tencent.*"},
		},
	})
	in := []krs.MatchableApp{
		{ID: "com.tencent.mm", InstallerPackageName: "com.xiaomi.market"},
		{ID: "com.foo.bar", InstallerPackageName: "com.xiaomi.market"},
		{ID: "com.unrelated", InstallerPackageName: "com.google.android.packageinstaller"},
	}
	got := krs.MatchInstalled(apps, in, "android")
	if len(got) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(got), got)
	}
	// First app: both installer + glob would match; installer wins (priority).
	if got[0].HitKind != "installer" || got[0].HitPattern != "com.xiaomi.market" {
		t.Errorf("[0] expected installer hit, got %+v", got[0])
	}
	// Second app: only installer matches.
	if got[1].HitKind != "installer" {
		t.Errorf("[1] expected installer hit, got %+v", got[1])
	}
}

// Desktop matchers iterate ProcessNames. An app with no process names
// (an Android-side row leaked into a desktop call, or a desktop app where
// the daemon couldn't enumerate processes) must not match anything.
// Regression guard against a future bug where empty == match-all.
func TestMatchInstalled_WindowsEmptyProcessNames(t *testing.T) {
	apps := roundTripApps(t, &krs.AppPatterns{
		Windows: krs.WindowsPatterns{Apps: []string{"wechat*"}},
	})
	in := []krs.MatchableApp{
		{ID: "noproc"},                       // ProcessNames omitted entirely
		{ID: "emptyproc", ProcessNames: nil}, // explicit nil
		{ID: "emptyslice", ProcessNames: []string{}},
	}
	if got := krs.MatchInstalled(apps, in, "windows"); len(got) != 0 {
		t.Errorf("windows with empty ProcessNames: expected 0 matches, got %d: %+v", len(got), got)
	}
}

func TestMatchInstalled_DesktopGOOSRouting(t *testing.T) {
	apps := roundTripApps(t, &krs.AppPatterns{
		Windows: krs.WindowsPatterns{Apps: []string{"WeChat*"}},
		Darwin:  krs.DarwinPatterns{Apps: []string{"WeChat*"}},
	})
	in := []krs.MatchableApp{
		{ID: "WeChat", ProcessNames: []string{"WeChat"}},
	}
	// On windows, query lowercased to "wechat" — pattern "wechat*" matches.
	if got := krs.MatchInstalled(apps, in, "windows"); len(got) != 1 {
		t.Errorf("windows: expected 1 match, got %d", len(got))
	}
	if got := krs.MatchInstalled(apps, in, "darwin"); len(got) != 1 {
		t.Errorf("darwin: expected 1 match, got %d", len(got))
	}
	// linux: no Linux patterns defined → no match.
	if got := krs.MatchInstalled(apps, in, "linux"); len(got) != 0 {
		t.Errorf("linux: expected 0 matches, got %d", len(got))
	}
	if got := krs.MatchInstalled(apps, in, "freebsd"); len(got) != 0 {
		t.Errorf("freebsd: expected 0 matches, got %d", len(got))
	}
}

func roundTripApps(t *testing.T, in *krs.AppPatterns) *krs.AppPatterns {
	t.Helper()
	b := &krs.Bundle{Apps: in}
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	out, err := krs.ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	return out.Apps
}
