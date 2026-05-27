package krs_test

import (
	"bytes"
	"testing"

	"github.com/kaitu-io/k2-rules/krs"
)

// Byte-exact: one Android installer, no routing data → header + 1 section.
// Payload: uvarint(len) + utf-8, no count prefix.
func TestWriteBundle_AndroidInstallers_OneEntry(t *testing.T) {
	var buf bytes.Buffer
	b := &krs.Bundle{Apps: &krs.AppPatterns{
		Android: krs.AndroidPatterns{Installers: []string{"com.xiaomi.market"}},
	}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	want := []byte{
		// Header
		'K', '2', 'R', 'L', 0x01, 0x00, 0x01, 0x00,
		// Index entry: AndroidInstallers (0x0100), off=18, len=18
		0x00, 0x01, 18, 0, 0, 0, 18, 0, 0, 0,
		// Payload: uvarint(17), "com.xiaomi.market"
		17, 'c', 'o', 'm', '.', 'x', 'i', 'a', 'o', 'm', 'i', '.', 'm', 'a', 'r', 'k', 'e', 't',
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("\n got: %x\nwant: %x", buf.Bytes(), want)
	}
}

// Writer sorts entries on emit; mixed-case Windows entries are also
// lowercased at compile (Windows is case-insensitive for app matching).
func TestWriteBundle_PlatformOrderingAndCase(t *testing.T) {
	var buf bytes.Buffer
	b := &krs.Bundle{Apps: &krs.AppPatterns{
		Android: krs.AndroidPatterns{
			Installers: []string{"com.zzz", "com.aaa"},      // sort
			Apps:       []string{"com.Tencent.*", "com.A.*"}, // sort, preserve case
		},
		Windows: krs.WindowsPatterns{Apps: []string{"WeChat*", "QQ*"}}, // sort + lower
		Darwin:  krs.DarwinPatterns{Apps: []string{"WeChat*"}},          // preserve case
	}}
	if err := krs.WriteBundle(&buf, b); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	got, err := krs.ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	if got.Apps == nil {
		t.Fatal("Apps nil after round-trip")
	}
	checkSlice(t, "Android.Installers", got.Apps.Android.Installers, []string{"com.aaa", "com.zzz"})
	checkSlice(t, "Android.Apps", got.Apps.Android.Apps, []string{"com.A.*", "com.Tencent.*"})
	checkSlice(t, "Windows.Apps", got.Apps.Windows.Apps, []string{"qq*", "wechat*"})
	checkSlice(t, "Darwin.Apps", got.Apps.Darwin.Apps, []string{"WeChat*"})
}

// Empty platforms produce no sections — round-tripping a bundle with only
// Android data leaves Windows/Darwin nil on the read side too.
func TestReadBundle_OmitsEmptyPlatforms(t *testing.T) {
	in := &krs.Bundle{Apps: &krs.AppPatterns{
		Android: krs.AndroidPatterns{Apps: []string{"com.x"}},
	}}
	var buf bytes.Buffer
	if err := krs.WriteBundle(&buf, in); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	got, err := krs.ReadBundle(buf.Bytes())
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	if got.Apps == nil {
		t.Fatal("Apps nil")
	}
	if len(got.Apps.Windows.Apps) != 0 || len(got.Apps.Darwin.Apps) != 0 {
		t.Errorf("expected empty Windows/Darwin, got %+v / %+v",
			got.Apps.Windows.Apps, got.Apps.Darwin.Apps)
	}
}

func checkSlice(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: len %d != %d (got=%v want=%v)", name, len(got), len(want), got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d]: got %q want %q", name, i, got[i], want[i])
		}
	}
}
