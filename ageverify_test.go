package main

import "testing"

func TestAgeVerifyServicesShape(t *testing.T) {
	if len(ageVerifyServices) != len(ageVerifyAnchors) {
		t.Fatalf("%d services but %d anchor groups — a set with no anchors ships unvalidated",
			len(ageVerifyServices), len(ageVerifyAnchors))
	}
	for _, s := range ageVerifyServices {
		anchors, ok := ageVerifyAnchors[s.Name]
		if !ok {
			t.Errorf("set %q has no anchors", s.Name)
			continue
		}
		// One anchor per v2fly file, or losing a file goes unnoticed as long
		// as some other file still satisfies the anchors that do exist.
		if len(anchors) != len(s.V2flyNames) {
			t.Errorf("set %q: %d anchors for %d v2fly sources, want 1:1",
				s.Name, len(anchors), len(s.V2flyNames))
		}
		if len(s.IPURLs) != 0 {
			t.Errorf("set %q carries IP sources; ageverify is domain-only", s.Name)
		}
	}
}

func TestValidateAgeVerify(t *testing.T) {
	anchors := map[string][]string{"a": {"x.com", "y.com"}}
	ok := []bundleSet{{Name: "a", Domains: []string{"x.com", "y.com", "z.com"}}}
	if err := validateAgeVerify(ok, anchors); err != nil {
		t.Errorf("covering set rejected: %v", err)
	}
	missingAnchor := []bundleSet{{Name: "a", Domains: []string{"x.com"}}}
	if err := validateAgeVerify(missingAnchor, anchors); err == nil {
		t.Error("set missing an anchor accepted, want error")
	}
	if err := validateAgeVerify(nil, anchors); err == nil {
		t.Error("missing set accepted, want error")
	}
}
