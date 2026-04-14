package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchDomainList_PlainFQDN(t *testing.T) {
	body := "example.com\nfoo.bar.org\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	domains, err := fetchDomainList(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"example.com", "foo.bar.org"}
	if len(domains) != len(want) {
		t.Fatalf("got %d domains, want %d: %v", len(domains), len(want), domains)
	}
	for i, d := range domains {
		if d != want[i] {
			t.Errorf("domain[%d] = %q, want %q", i, d, want[i])
		}
	}
}

func TestFetchDomainList_V2rayPrefixes(t *testing.T) {
	body := strings.Join([]string{
		"domain:example.com",
		"domain:foo.bar.org",
		"full:exact.match.net",
		"plain.domain.io",
		"# comment line",
		"",
		"domain:with-trailing.space.com  ",
	}, "\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	domains, err := fetchDomainList(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"example.com", "foo.bar.org", "exact.match.net", "plain.domain.io", "with-trailing.space.com"}
	if len(domains) != len(want) {
		t.Fatalf("got %d domains, want %d: %v", len(domains), len(want), domains)
	}
	for i, d := range domains {
		if d != want[i] {
			t.Errorf("domain[%d] = %q, want %q", i, d, want[i])
		}
	}
}

func TestFetchDomainList_CommentsAndBlanks(t *testing.T) {
	body := "# Title: blocklist\n# Description: test\n\nexample.com\n\n# another comment\nfoo.org\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	domains, err := fetchDomainList(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("got %d domains, want 2: %v", len(domains), domains)
	}
}

func TestFetchDomainList_IPsRejected(t *testing.T) {
	body := "1.2.3.4\nexample.com\n192.168.1.1\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	domains, err := fetchDomainList(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// IPs should be rejected by extractHost (no dots in hostname after parse, or parsed as IP).
	if len(domains) != 1 || domains[0] != "example.com" {
		t.Fatalf("got %v, want [example.com]", domains)
	}
}

func TestFetchDomainList_InlineComments(t *testing.T) {
	body := "example.com # some note\ndomain:foo.org # v2ray entry\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	domains, err := fetchDomainList(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"example.com", "foo.org"}
	if len(domains) != len(want) {
		t.Fatalf("got %d domains, want %d: %v", len(domains), len(want), domains)
	}
	for i, d := range domains {
		if d != want[i] {
			t.Errorf("domain[%d] = %q, want %q", i, d, want[i])
		}
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"http://example.com/path", "example.com"},
		{"https://FOO.Bar.COM:8080/x?y=z", "foo.bar.com"},
		{"1.2.3.4", ""},           // IP rejected
		{"localhost", ""},          // no dot
		{"", ""},                   // empty
		{"http://", ""},            // no host
		{"foo bar.com", ""},        // space in host
	}
	for _, tt := range tests {
		got := extractHost(tt.input)
		if got != tt.want {
			t.Errorf("extractHost(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
