package main

import "testing"

func TestGamesServicesShape(t *testing.T) {
	if len(gamesServices) != 2 {
		t.Fatalf("gamesServices has %d entries, want 2 (sites + ip)", len(gamesServices))
	}
	byName := map[string]service{}
	for _, s := range gamesServices {
		byName[s.Name] = s
	}
	sites, ok := byName["games-sites"]
	if !ok {
		t.Fatal("missing games-sites service")
	}
	if len(sites.V2flyNames) == 0 {
		t.Error("games-sites has no v2fly source")
	}
	ip, ok := byName["games-ip"]
	if !ok {
		t.Fatal("missing games-ip service")
	}
	if len(ip.IPURLs) == 0 {
		t.Error("games-ip has no ASN source")
	}
	if len(gamesAnchors) == 0 {
		t.Error("gamesAnchors is empty — the build would ship an unvalidated set")
	}
	if len(gamesAnchors) != len(ip.IPURLs) {
		t.Errorf("gamesAnchors has %d entries but games-ip has %d IPURLs — "+
			"every ASN feed must have its own anchor, or validateGames' "+
			"fail-closed guard silently degrades to \"at least one feed is "+
			"still alive\" instead of \"every feed is still alive\": with N "+
			"anchors < M feeds, an anchor can be satisfied by a surviving "+
			"feed even after (M-N) other feeds go empty or get reassigned",
			len(gamesAnchors), len(ip.IPURLs))
	}
}

func TestValidateGames(t *testing.T) {
	// A set that covers the anchor passes.
	if err := validateGames([]string{"203.0.113.0/24"}, []string{"203.0.113.7"}); err != nil {
		t.Errorf("covering set rejected: %v", err)
	}
	// A set that misses the anchor fails closed.
	if err := validateGames([]string{"198.51.100.0/24"}, []string{"203.0.113.7"}); err == nil {
		t.Error("non-covering set accepted, want error (fail-closed guard is off)")
	}
	// An empty set fails closed.
	if err := validateGames(nil, []string{"203.0.113.7"}); err == nil {
		t.Error("empty set accepted, want error")
	}
}
