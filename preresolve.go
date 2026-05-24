package main

// Build-time DNS pre-resolution for HTTPDNS anchor IPs.
//
// HTTPDNS servers (httpdns.aliyun.com, dns.weixin.qq.com, etc.) are operated
// behind GeoDNS so the IP a client sees depends on the client's source IP:
// a CN client gets a mainland PoP, a HK client gets a HK PoP, a US client
// gets a US PoP. When a Kaitu user inside China runs the VPN and an app
// (WeChat is the canonical case) connects to HTTPDNS via a hardcoded IP not
// pinned by runtime DNS pipeline, that connection goes via the VPN out to
// e.g. AU. The HTTPDNS server then sees an AU source IP and returns
// overseas-optimized business IPs (e.g. Tencent HK 43.155.124.0/24), and the
// app gets routed AU→CN→HK for what should be a local connection.
//
// Fix: at build time, query every HTTPDNS domain in v2fly category-httpdns-cn
// from multiple geographic perspectives via EDNS0 Client Subnet, union all
// resulting IPs, and pin them as direct in the CN bundle. This covers all PoP
// IPs the app might end up using, regardless of where the app got the IP.

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// resolverSpec describes one DNS query channel: a server and (optionally) the
// EDNS0 Client Subnet to advertise. ECS lets us query from many "client
// locations" while staying physically on one GitHub runner.
type resolverSpec struct {
	Addr  string       // "8.8.8.8:53"
	ECS   netip.Prefix // zero value = no ECS option attached
	Label string       // human-readable, for logs
}

// preResolveConfig controls pre-resolution behavior. Constructed once per
// build invocation via defaultPreResolveConfig; tests override fields directly.
type preResolveConfig struct {
	Resolvers       []resolverSpec
	PerQueryTimeout time.Duration // per-(domain, resolver, qtype) DNS exchange budget
	BatchTimeout    time.Duration // hard cap on the entire batch — protects CI
	MaxParallel     int           // max in-flight domains (each fans out to all resolvers)
}

// defaultPreResolveConfig returns production defaults. The resolver set is
// designed to cover all PoP geographies that real-world HTTPDNS servers route
// to. ECS is the only way to make this work from a single runner — without it
// we'd only see whatever PoP serves Azure US-East-2 (where GitHub runners
// live), and would miss CN/HK/AU/SG PoPs entirely.
//
// Resolver mix rationale:
//   - 8.8.8.8 honors ECS and is the workhorse for geographic diversity.
//     We probe CN/HK/US/AU/SG-representative subnets.
//   - 1.1.1.1 deliberately strips ECS for privacy. Including it gives us a
//     vendor cross-check and catches PoPs Google misses.
//   - 9.9.9.9 (Quad9) for one more independent view.
//
// Subnet picks are stable, public, well-known anchor prefixes — APNIC for
// CN/HK/AU, ARIN/AWS for US, Singtel/AS3758 for SG. They don't need to be
// "real" client IPs, only correct GeoIP-attributable.
func defaultPreResolveConfig() preResolveConfig {
	return preResolveConfig{
		Resolvers: []resolverSpec{
			{Addr: "8.8.8.8:53", ECS: netip.MustParsePrefix("1.0.1.0/24"), Label: "Google-ECS-CN"},        // CNNIC
			{Addr: "8.8.8.8:53", ECS: netip.MustParsePrefix("210.0.176.0/24"), Label: "Google-ECS-HK"},   // HK APNIC
			{Addr: "8.8.8.8:53", ECS: netip.MustParsePrefix("18.220.0.0/24"), Label: "Google-ECS-US"},    // AWS us-east-2
			{Addr: "8.8.8.8:53", ECS: netip.MustParsePrefix("1.40.0.0/24"), Label: "Google-ECS-AU"},      // AU Telstra
			{Addr: "8.8.8.8:53", ECS: netip.MustParsePrefix("203.116.0.0/24"), Label: "Google-ECS-SG"},   // Singtel
			{Addr: "8.8.8.8:53", Label: "Google-no-ECS"},                                                  // Runner-native view
			{Addr: "1.1.1.1:53", Label: "Cloudflare-no-ECS"},                                              // Vendor cross-check
			{Addr: "9.9.9.9:53", Label: "Quad9-no-ECS"},                                                   // Independent third view
		},
		PerQueryTimeout: 3 * time.Second,
		BatchTimeout:    5 * time.Minute,
		MaxParallel:     8,
	}
}

// preResolveDomains queries each domain against every resolver, unions the
// observed IPs, filters private/reserved addresses, and returns sorted /32
// (or /128) CIDR strings. The function never returns an error: any DNS
// failure is logged and the batch continues with whatever it managed to
// gather. This is intentional — pre-resolve is supplementary data, and
// failing the entire build because Google's DNS hiccuped would be a
// terrible CI experience.
//
// A domain is counted as "resolved" when at least one resolver returned a
// successful response (rcode=0), even if the answer section was empty
// (HTTPDNS servers commonly have no AAAA records — that's not a failure).
func preResolveDomains(ctx context.Context, domains []string, cfg preResolveConfig) []string {
	if len(domains) == 0 || len(cfg.Resolvers) == 0 {
		return nil
	}

	var mu sync.Mutex
	seenAddrs := make(map[netip.Addr]struct{})
	resolvedCount := 0

	sem := make(chan struct{}, cfg.MaxParallel)
	var wg sync.WaitGroup

	for _, d := range domains {
		if ctx.Err() != nil {
			log.Printf("    preresolve: batch ctx canceled at %s — partial result", d)
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }()

			addrs, ok := resolveOneDomain(ctx, domain, cfg)
			if !ok {
				log.Printf("    preresolve: %s — all resolvers failed", domain)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			resolvedCount++
			for _, a := range addrs {
				if shouldSkipIP(a) {
					continue
				}
				seenAddrs[a.Unmap()] = struct{}{}
			}
		}(d)
	}
	wg.Wait()

	cidrs := make([]string, 0, len(seenAddrs))
	for a := range seenAddrs {
		bits := 32
		if a.Is6() {
			bits = 128
		}
		cidrs = append(cidrs, netip.PrefixFrom(a, bits).String())
	}
	sort.Strings(cidrs)

	log.Printf("    preresolve summary: %d/%d domains resolved → %d unique IPs",
		resolvedCount, len(domains), len(cidrs))
	return cidrs
}

// resolveOneDomain queries A and AAAA for one domain across every resolver and
// returns the union of observed IPs. Returns ok=false only when every single
// (resolver, qtype) pair errored — partial success counts as success.
func resolveOneDomain(ctx context.Context, domain string, cfg preResolveConfig) ([]netip.Addr, bool) {
	var addrs []netip.Addr
	anyResolverOK := false
	for _, r := range cfg.Resolvers {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			qctx, cancel := context.WithTimeout(ctx, cfg.PerQueryTimeout)
			got, err := queryOneResolver(qctx, domain, qtype, r)
			cancel()
			if err != nil {
				continue
			}
			anyResolverOK = true
			addrs = append(addrs, got...)
		}
	}
	return addrs, anyResolverOK
}

// queryOneResolver sends a single DNS query and returns A/AAAA answers as
// netip.Addr. Errors surface for transport failures, timeouts, and non-success
// rcodes (NXDOMAIN, SERVFAIL, etc.). Empty answer sets return (nil, nil) —
// that's a successful "no records" response and the caller treats it as such.
func queryOneResolver(ctx context.Context, domain string, qtype uint16, r resolverSpec) ([]netip.Addr, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	if r.ECS.IsValid() {
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(4096)
		ecs := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			SourceNetmask: uint8(r.ECS.Bits()),
			SourceScope:   0,
		}
		if r.ECS.Addr().Is4() {
			ecs.Family = 1
			ecs.Address = r.ECS.Addr().AsSlice()
		} else {
			ecs.Family = 2
			ecs.Address = r.ECS.Addr().AsSlice()
		}
		opt.Option = append(opt.Option, ecs)
		msg.Extra = append(msg.Extra, opt)
	}

	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, r.Addr)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
	}

	var out []netip.Addr
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(rr.A); ok {
				out = append(out, a.Unmap())
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(rr.AAAA); ok {
				out = append(out, a.Unmap())
			}
		}
	}
	return out, nil
}

// shouldSkipIP returns true for addresses that have no business in a routing
// rule set: private RFC1918, loopback, link-local, multicast, unspecified,
// etc. These can legitimately appear in DNS answers (CDN edge debug records,
// misconfigured authoritative servers) and would silently cause routing bugs
// if pinned as "direct".
func shouldSkipIP(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	return a.IsPrivate() ||
		a.IsLoopback() ||
		a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() ||
		a.IsMulticast() ||
		a.IsUnspecified() ||
		a.IsInterfaceLocalMulticast()
}
