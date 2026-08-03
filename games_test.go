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
}
