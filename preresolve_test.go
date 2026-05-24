package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mockDNSServer is a minimal in-process DNS server backed by a callback so each
// test can shape responses arbitrarily. Returns the addr "127.0.0.1:NNNNN".
type mockDNSServer struct {
	addr     string
	server   *dns.Server
	handler  func(w dns.ResponseWriter, m *dns.Msg)
	shutdown func()
}

func startMockDNS(t *testing.T, handler func(w dns.ResponseWriter, m *dns.Msg)) *mockDNSServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Net:        "udp",
		Handler:    dns.HandlerFunc(handler),
	}
	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = srv.ActivateAndServe() }()
	<-ready
	return &mockDNSServer{
		addr:     pc.LocalAddr().String(),
		server:   srv,
		handler:  handler,
		shutdown: func() { _ = srv.Shutdown() },
	}
}

// answerA helper: build an authoritative A response with the given IPv4s.
func answerA(req *dns.Msg, ips ...string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	for _, ip := range ips {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(ip).To4(),
		})
	}
	return resp
}

// answerAAAA helper.
func answerAAAA(req *dns.Msg, ips ...string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	for _, ip := range ips {
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP(ip).To16(),
		})
	}
	return resp
}

// emptyOK helper: NoError response with empty answer (typical for AAAA on
// IPv4-only HTTPDNS hosts).
func emptyOK(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	return resp
}

func TestPreResolve_MultiResolverUnion(t *testing.T) {
	// Resolver A says 1.1.1.1; resolver B says 2.2.2.2. Union should hold both.
	srvA := startMockDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		if m.Question[0].Qtype == dns.TypeA {
			_ = w.WriteMsg(answerA(m, "1.1.1.1"))
		} else {
			_ = w.WriteMsg(emptyOK(m))
		}
	})
	defer srvA.shutdown()
	srvB := startMockDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		if m.Question[0].Qtype == dns.TypeA {
			_ = w.WriteMsg(answerA(m, "2.2.2.2"))
		} else {
			_ = w.WriteMsg(emptyOK(m))
		}
	})
	defer srvB.shutdown()

	cfg := preResolveConfig{
		Resolvers: []resolverSpec{
			{Addr: srvA.addr, Label: "A"},
			{Addr: srvB.addr, Label: "B"},
		},
		PerQueryTimeout: 2 * time.Second,
		BatchTimeout:    10 * time.Second,
		MaxParallel:     2,
	}
	got := preResolveDomains(context.Background(), []string{"example.com"}, cfg)

	want := map[string]bool{"1.1.1.1/32": true, "2.2.2.2/32": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want union of %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected CIDR in union: %s", g)
		}
	}
}

func TestPreResolve_PartialResolverFailureStillSucceeds(t *testing.T) {
	// Resolver A returns 1.1.1.1; resolver B is unreachable (closed port).
	// Domain should still resolve and 1.1.1.1 should be included.
	srvA := startMockDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		if m.Question[0].Qtype == dns.TypeA {
			_ = w.WriteMsg(answerA(m, "1.1.1.1"))
		} else {
			_ = w.WriteMsg(emptyOK(m))
		}
	})
	defer srvA.shutdown()

	// Bind a port and immediately close — anything sent there will time out.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := pc.LocalAddr().String()
	pc.Close()

	cfg := preResolveConfig{
		Resolvers: []resolverSpec{
			{Addr: srvA.addr, Label: "A"},
			{Addr: deadAddr, Label: "DEAD"},
		},
		PerQueryTimeout: 500 * time.Millisecond, // short — don't slow tests
		BatchTimeout:    5 * time.Second,
		MaxParallel:     2,
	}
	got := preResolveDomains(context.Background(), []string{"example.com"}, cfg)
	if len(got) != 1 || got[0] != "1.1.1.1/32" {
		t.Fatalf("got %v, want [1.1.1.1/32]", got)
	}
}

func TestPreResolve_AllResolversFailReturnsEmpty(t *testing.T) {
	// Two dead resolvers. Function returns empty without panicking.
	pc1, _ := net.ListenPacket("udp", "127.0.0.1:0")
	pc2, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr1, addr2 := pc1.LocalAddr().String(), pc2.LocalAddr().String()
	pc1.Close()
	pc2.Close()

	cfg := preResolveConfig{
		Resolvers: []resolverSpec{
			{Addr: addr1, Label: "DEAD1"},
			{Addr: addr2, Label: "DEAD2"},
		},
		PerQueryTimeout: 300 * time.Millisecond,
		BatchTimeout:    3 * time.Second,
		MaxParallel:     2,
	}
	got := preResolveDomains(context.Background(), []string{"example.com"}, cfg)
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestPreResolve_PrivateAndReservedFiltered(t *testing.T) {
	srv := startMockDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		switch m.Question[0].Qtype {
		case dns.TypeA:
			// Mix of valid and invalid IPs.
			_ = w.WriteMsg(answerA(m,
				"8.8.8.8",     // public — keep
				"10.0.0.1",    // private — drop
				"127.0.0.1",   // loopback — drop
				"169.254.1.1", // link-local — drop
				"224.0.0.1",   // multicast — drop
				"0.0.0.0",     // unspecified — drop
			))
		case dns.TypeAAAA:
			_ = w.WriteMsg(answerAAAA(m,
				"2606:4700:4700::1111", // public — keep
				"::1",                  // loopback — drop
				"fe80::1",              // link-local — drop
				"fc00::1",              // private (ULA) — drop
			))
		}
	})
	defer srv.shutdown()

	cfg := preResolveConfig{
		Resolvers:       []resolverSpec{{Addr: srv.addr, Label: "S"}},
		PerQueryTimeout: 1 * time.Second,
		BatchTimeout:    3 * time.Second,
		MaxParallel:     1,
	}
	got := preResolveDomains(context.Background(), []string{"x.com"}, cfg)

	want := map[string]bool{"8.8.8.8/32": true, "2606:4700:4700::1111/128": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v (private/reserved should be filtered)", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected CIDR survived filter: %s", g)
		}
	}
}

func TestPreResolve_ECSPropagatedToServer(t *testing.T) {
	// Server records the EDNS0_SUBNET option from each incoming query so we
	// can verify our config translated to the wire correctly.
	var mu sync.Mutex
	seenECS := make(map[string]bool) // family:bits:address → true
	srv := startMockDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		opt := m.IsEdns0()
		if opt != nil {
			for _, o := range opt.Option {
				if ecs, ok := o.(*dns.EDNS0_SUBNET); ok {
					key := pack(int(ecs.Family), int(ecs.SourceNetmask), ecs.Address.String())
					mu.Lock()
					seenECS[key] = true
					mu.Unlock()
				}
			}
		}
		if m.Question[0].Qtype == dns.TypeA {
			_ = w.WriteMsg(answerA(m, "1.1.1.1"))
		} else {
			_ = w.WriteMsg(emptyOK(m))
		}
	})
	defer srv.shutdown()

	cfg := preResolveConfig{
		Resolvers: []resolverSpec{
			{Addr: srv.addr, ECS: netip.MustParsePrefix("1.2.3.0/24"), Label: "ECS-test"},
		},
		PerQueryTimeout: 1 * time.Second,
		BatchTimeout:    3 * time.Second,
		MaxParallel:     1,
	}
	_ = preResolveDomains(context.Background(), []string{"x.com"}, cfg)

	mu.Lock()
	defer mu.Unlock()
	wantKey := pack(1, 24, "1.2.3.0") // family=1 (IPv4), mask=24, addr=1.2.3.0
	if !seenECS[wantKey] {
		t.Fatalf("ECS not propagated correctly. seen=%v want=%s", seenECS, wantKey)
	}
}

func TestPreResolve_NoECSWhenPrefixUnset(t *testing.T) {
	// Empty resolverSpec.ECS (zero netip.Prefix) → no OPT record sent.
	var gotECS bool
	var mu sync.Mutex
	srv := startMockDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		opt := m.IsEdns0()
		if opt != nil {
			for _, o := range opt.Option {
				if _, ok := o.(*dns.EDNS0_SUBNET); ok {
					mu.Lock()
					gotECS = true
					mu.Unlock()
				}
			}
		}
		_ = w.WriteMsg(answerA(m, "1.1.1.1"))
	})
	defer srv.shutdown()

	cfg := preResolveConfig{
		Resolvers:       []resolverSpec{{Addr: srv.addr, Label: "no-ECS"}},
		PerQueryTimeout: 1 * time.Second,
		BatchTimeout:    3 * time.Second,
		MaxParallel:     1,
	}
	_ = preResolveDomains(context.Background(), []string{"x.com"}, cfg)

	mu.Lock()
	defer mu.Unlock()
	if gotECS {
		t.Fatalf("ECS option sent despite zero-value Prefix in config")
	}
}

func TestPreResolve_NXDOMAINTreatedAsFailure(t *testing.T) {
	// Server returns NXDOMAIN. Domain should be reported as "all resolvers
	// failed" since no positive evidence was gathered.
	srv := startMockDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(resp)
	})
	defer srv.shutdown()

	cfg := preResolveConfig{
		Resolvers:       []resolverSpec{{Addr: srv.addr, Label: "NX"}},
		PerQueryTimeout: 1 * time.Second,
		BatchTimeout:    3 * time.Second,
		MaxParallel:     1,
	}
	got := preResolveDomains(context.Background(), []string{"nope.invalid"}, cfg)
	if len(got) != 0 {
		t.Fatalf("got %v, want empty (NXDOMAIN should not produce IPs)", got)
	}
}

func TestPreResolve_EmptyAnswerStillCountsResolverAsHealthy(t *testing.T) {
	// HTTPDNS hosts typically have no AAAA. A successful empty answer must
	// NOT be confused with resolver failure. So a domain with A=1.1.1.1 and
	// AAAA=empty should produce {1.1.1.1/32} and one resolver counted.
	srv := startMockDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		if m.Question[0].Qtype == dns.TypeA {
			_ = w.WriteMsg(answerA(m, "1.1.1.1"))
		} else {
			_ = w.WriteMsg(emptyOK(m))
		}
	})
	defer srv.shutdown()

	cfg := preResolveConfig{
		Resolvers:       []resolverSpec{{Addr: srv.addr, Label: "S"}},
		PerQueryTimeout: 1 * time.Second,
		BatchTimeout:    3 * time.Second,
		MaxParallel:     1,
	}
	got := preResolveDomains(context.Background(), []string{"v4only.com"}, cfg)
	if len(got) != 1 || got[0] != "1.1.1.1/32" {
		t.Fatalf("got %v, want [1.1.1.1/32]", got)
	}
}

func TestPreResolve_OutputDeterministicallySorted(t *testing.T) {
	// Bundle SHA stability requires deterministic ordering. We feed the
	// server responses in a non-sorted order and verify output is sorted.
	srv := startMockDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		if m.Question[0].Qtype == dns.TypeA {
			_ = w.WriteMsg(answerA(m, "9.9.9.9", "1.1.1.1", "5.5.5.5"))
		} else {
			_ = w.WriteMsg(emptyOK(m))
		}
	})
	defer srv.shutdown()

	cfg := preResolveConfig{
		Resolvers:       []resolverSpec{{Addr: srv.addr, Label: "S"}},
		PerQueryTimeout: 1 * time.Second,
		BatchTimeout:    3 * time.Second,
		MaxParallel:     1,
	}
	got := preResolveDomains(context.Background(), []string{"x.com"}, cfg)
	want := []string{"1.1.1.1/32", "5.5.5.5/32", "9.9.9.9/32"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v (must be sorted ascending)", got, want)
	}
}

func TestPreResolve_EmptyDomainListReturnsEmpty(t *testing.T) {
	got := preResolveDomains(context.Background(), nil, defaultPreResolveConfig())
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestPreResolve_NoResolversReturnsEmpty(t *testing.T) {
	got := preResolveDomains(context.Background(), []string{"x.com"}, preResolveConfig{})
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

// pack is a tiny helper for the ECS-propagation test key.
func pack(family, mask int, addr string) string {
	return fmt.Sprintf("%d:%d:%s", family, mask, addr)
}
