// k2-rules-gen compiles domain and IP-CIDR data from open sources into .k2b bundle files.
//
// Usage: go run . [-o output_dir]
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	outDir := flag.String("o", "dist", "output directory")
	onlyCountry := flag.String("country", "", "build only this country code (for local testing, e.g. -country=ru)")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	// Clone v2fly domain list (shallow).
	v2flyDir, err := cloneV2fly()
	if err != nil {
		log.Fatalf("clone v2fly: %v", err)
	}
	defer os.RemoveAll(v2flyDir)

	// Build overseas bundle (single-set "overseas" + non-CN IP complement).
	// Skipped when -country is specified for faster local iteration.
	if *onlyCountry == "" {
		log.Println("=== building overseas.k2b ===")
		overseasSets, err := buildSets(overseasServices, v2flyDir)
		if err != nil {
			log.Fatalf("build overseas: %v", err)
		}
		if err := writeK2B(filepath.Join(*outDir, "overseas.k2b"), overseasSets); err != nil {
			log.Fatalf("write overseas.k2b: %v", err)
		}
	}

	// Build per-country bundles: {cc}-direct.k2b for each country in the table.
	for _, c := range countries {
		if *onlyCountry != "" && c.Code != *onlyCountry {
			continue
		}
		bundleName := c.Code + "-direct.k2b"
		log.Printf("=== building %s (%s) ===", bundleName, c.Name)
		sets, err := buildSets(c.Services, v2flyDir)
		if err != nil {
			log.Fatalf("build %s: %v", bundleName, err)
		}
		if err := writeK2B(filepath.Join(*outDir, bundleName), sets); err != nil {
			log.Fatalf("write %s: %v", bundleName, err)
		}
	}

	// Generate manifest from whatever .k2b files are present in the output dir.
	manifest := buildManifest(*outDir)
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(*outDir, "manifest.json"), manifestData, 0644); err != nil {
		log.Fatalf("write manifest: %v", err)
	}

	log.Println("=== done ===")
	log.Printf("output: %s\n", *outDir)
}

// cloneV2fly does a shallow clone of v2fly/domain-list-community.
func cloneV2fly() (string, error) {
	dir, err := os.MkdirTemp("", "v2fly-*")
	if err != nil {
		return "", err
	}
	log.Println("fetching v2fly/domain-list-community...")
	url := "https://github.com/v2fly/domain-list-community/archive/refs/heads/master.tar.gz"
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetch v2fly: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fetch v2fly: status %d", resp.StatusCode)
	}
	// Extract tarball.
	cmd := fmt.Sprintf("tar xzf - -C %s --strip-components=1", dir)
	return dir, runPipe(cmd, resp.Body)
}

func runPipe(cmd string, stdin io.Reader) error {
	c := execCommand("sh", "-c", cmd)
	c.Stdin = stdin
	c.Stdout = os.Stderr
	c.Stderr = os.Stderr
	return c.Run()
}

// buildSets builds BundleSet data for a list of services.
func buildSets(svcs []service, v2flyDir string) ([]bundleSet, error) {
	var sets []bundleSet
	for _, svc := range svcs {
		log.Printf("  %s: ", svc.Name)

		var domains, excludeDomains []string

		// v2fly domain-list-community data files.
		for _, name := range svc.V2flyNames {
			visited := make(map[string]bool)
			inc, exc, err := parseV2flyRecursive(filepath.Join(v2flyDir, "data"), name, svc.ExcludeAttr, visited)
			if err != nil {
				log.Printf("    WARN: v2fly/%s: %v", name, err)
				continue
			}
			domains = append(domains, inc...)
			excludeDomains = append(excludeDomains, exc...)
			log.Printf("    v2fly/%s: %d domains, %d excludes (%d files)", name, len(inc), len(exc), len(visited))
		}

		// Citizen Lab test-lists CSV — URL-format, one URL per row.
		if svc.CitizenLabCSVURL != "" {
			hosts, err := fetchCitizenLabCSV(svc.CitizenLabCSVURL)
			if err != nil {
				log.Printf("    WARN: citizenlab %s: %v", svc.CitizenLabCSVURL, err)
			} else {
				domains = append(domains, hosts...)
				log.Printf("    citizenlab/%s: %d hosts", filepath.Base(svc.CitizenLabCSVURL), len(hosts))
			}
		}

		// Plaintext domain lists (one FQDN per line).
		for _, u := range svc.DomainListURLs {
			doms, err := fetchDomainList(u)
			if err != nil {
				log.Printf("    WARN: domainlist %s: %v", u, err)
				continue
			}
			domains = append(domains, doms...)
			log.Printf("    domainlist/%s: %d domains", filepath.Base(u), len(doms))
		}

		// Hardcoded orphan domains.
		if len(svc.OrphanDomains) > 0 {
			domains = append(domains, svc.OrphanDomains...)
			log.Printf("    orphans: %d domains", len(svc.OrphanDomains))
		}

		// IP CIDR sources.
		var cidrs []string
		for _, u := range svc.IPURLs {
			c, err := fetchCIDRs(u)
			if err != nil {
				log.Printf("    WARN: %s: %v", u, err)
				continue
			}
			cidrs = append(cidrs, c...)
			log.Printf("    %s: %d CIDRs", filepath.Base(u), len(c))
		}

		// Compute complement if configured (e.g. "all non-Chinese IPs").
		if svc.ComplementIPURL != "" {
			excludeCIDRs, err := fetchCIDRs(svc.ComplementIPURL)
			if err != nil {
				log.Printf("    WARN: complement %s: %v", svc.ComplementIPURL, err)
			} else {
				comp := computeComplement(excludeCIDRs)
				cidrs = append(cidrs, comp...)
				log.Printf("    complement of %s: %d CIDRs (from %d exclude ranges)",
					filepath.Base(svc.ComplementIPURL), len(comp), len(excludeCIDRs))
			}
		}

		// Deduplicate.
		domains = dedup(domains)
		excludeDomains = dedup(excludeDomains)
		cidrs = dedup(cidrs)

		log.Printf("  → %s: %d domains, %d excludes, %d CIDRs\n", svc.Name, len(domains), len(excludeDomains), len(cidrs))
		sets = append(sets, bundleSet{
			Name:           svc.Name,
			Domains:        domains,
			ExcludeDomains: excludeDomains,
			CIDRs:          cidrs,
		})
	}
	return sets, nil
}

// fetchCitizenLabCSV fetches a citizenlab/test-lists CSV and returns a deduped
// list of hostnames. The CSV format has a header row and column 0 is a URL;
// we parse each URL and extract its host component (lowercased, port stripped).
//
// Malformed rows are silently skipped. License: CC-BY-SA 4.0 — attribution
// must be carried in ATTRIBUTIONS.md.
func fetchCitizenLabCSV(u string) ([]string, error) {
	resp, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	r := csv.NewReader(resp.Body)
	r.FieldsPerRecord = -1 // tolerate variable column counts
	r.LazyQuotes = true

	var hosts []string
	seen := make(map[string]bool)
	rowNum := 0
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip the malformed row and continue.
			continue
		}
		rowNum++
		if rowNum == 1 {
			continue // header
		}
		if len(row) == 0 {
			continue
		}
		raw := strings.TrimSpace(row[0])
		if raw == "" {
			continue
		}
		host := extractHost(raw)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	return hosts, nil
}

// extractHost parses a URL (or bare hostname) and returns the normalized host:
// scheme/path/query/fragment stripped, lowercased, port removed.
// Returns "" for inputs that don't yield a valid DNS hostname.
func extractHost(raw string) string {
	// Accept bare hostnames without scheme by synthesizing one.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	// Reject IP literals — rule engine expects DNS suffixes, not IPs.
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	// Reject obvious malformed hosts.
	if strings.ContainsAny(host, " \t/") || !strings.Contains(host, ".") {
		return ""
	}
	return host
}

// fetchDomainList fetches a plaintext domain list (one FQDN per line, # comments).
// Used for sources like bootmortis/iran-hosted-domains.
func fetchDomainList(u string) ([]string, error) {
	resp, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var domains []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comment.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		host := extractHost(line)
		if host != "" {
			domains = append(domains, host)
		}
	}
	return domains, scanner.Err()
}

// parseV2flyRecursive parses a v2fly domain-list-community data file,
// recursively resolving include: directives.
//
// Entries with @{excludeAttr} are collected into the exclude list (not dropped).
// This enables suffix exclusion: weibo.com is included, hk.weibo.com @!cn is excluded.
// MatchDomain checks excludes first — if hk.weibo.com matches an exclude, it won't
// match even though weibo.com suffix covers it.
//
// visited tracks already-parsed files to prevent infinite loops.
func parseV2flyRecursive(dataDir, name, excludeAttr string, visited map[string]bool) (includes []string, excludes []string, err error) {
	if visited[name] {
		return nil, nil, nil
	}
	visited[name] = true

	path := filepath.Join(dataDir, name)
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Check attributes before stripping them.
		attrs := ""
		if idx := strings.Index(line, " @"); idx >= 0 {
			attrs = line[idx:]
			line = strings.TrimSpace(line[:idx])
		}

		isExcluded := excludeAttr != "" && strings.Contains(attrs, "@"+excludeAttr)

		// Handle prefixes.
		switch {
		case strings.HasPrefix(line, "include:"):
			incName := strings.TrimPrefix(line, "include:")
			if idx := strings.Index(incName, " "); idx >= 0 {
				incName = incName[:idx]
			}
			incName = strings.TrimSpace(incName)
			subInc, subExc, err := parseV2flyRecursive(dataDir, incName, excludeAttr, visited)
			if err != nil {
				log.Printf("      WARN: include %s: %v", incName, err)
				continue
			}
			includes = append(includes, subInc...)
			excludes = append(excludes, subExc...)
		case strings.HasPrefix(line, "regexp:"):
			continue
		case strings.HasPrefix(line, "keyword:"):
			continue
		case strings.HasPrefix(line, "full:"):
			domain := strings.TrimSpace(strings.TrimPrefix(line, "full:"))
			if isExcluded {
				excludes = append(excludes, domain)
			} else {
				includes = append(includes, domain)
			}
		default:
			if line != "" {
				if isExcluded {
					excludes = append(excludes, line)
				} else {
					includes = append(includes, line)
				}
			}
		}
	}
	return includes, excludes, scanner.Err()
}

// fetchCIDRs fetches a URL returning one CIDR per line.
func fetchCIDRs(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var cidrs []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Validate it's a parseable prefix.
		if _, err := netip.ParsePrefix(line); err != nil {
			// Try as single IP.
			if _, err := netip.ParseAddr(line); err != nil {
				continue
			}
			line += "/32" // single IP → /32
		}
		cidrs = append(cidrs, line)
	}
	return cidrs, scanner.Err()
}

// computeComplement takes a list of CIDRs to exclude and returns all public
// IP ranges NOT covered by them. Private/reserved ranges are also excluded.
// Result: every public IP on the internet minus the exclude list.
func computeComplement(excludeCIDRs []string) []string {
	// Parse exclude ranges into v4 and v6 sets.
	var v4Exclude, v6Exclude []netip.Prefix
	for _, s := range excludeCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		p = p.Masked()
		if p.Addr().Is4() {
			v4Exclude = append(v4Exclude, p)
		} else {
			v6Exclude = append(v6Exclude, p)
		}
	}

	// Private/reserved ranges to also exclude.
	privateV4 := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	}
	privateV6 := []string{
		"::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
		"::ffff:0:0/96",  // IPv4-mapped
		"64:ff9b::/96",   // NAT64
		"100::/64",       // discard
		"2001:db8::/32",  // documentation
	}
	for _, s := range privateV4 {
		p, _ := netip.ParsePrefix(s)
		v4Exclude = append(v4Exclude, p.Masked())
	}
	for _, s := range privateV6 {
		p, _ := netip.ParsePrefix(s)
		v6Exclude = append(v6Exclude, p.Masked())
	}

	var result []string
	result = append(result, subtractPrefixes(netip.MustParsePrefix("0.0.0.0/0"), v4Exclude)...)
	result = append(result, subtractPrefixes(netip.MustParsePrefix("::/0"), v6Exclude)...)
	return result
}

// subtractPrefixes computes universe minus all exclude prefixes.
// Returns the remaining prefixes as CIDR strings.
func subtractPrefixes(universe netip.Prefix, excludes []netip.Prefix) []string {
	// Start with the full universe as a set of remaining prefixes.
	remaining := []netip.Prefix{universe}

	for _, excl := range excludes {
		var next []netip.Prefix
		for _, r := range remaining {
			if !r.Overlaps(excl) {
				next = append(next, r)
				continue
			}
			// Subtract excl from r by splitting r into halves recursively.
			next = append(next, subtractOne(r, excl)...)
		}
		remaining = next
	}

	result := make([]string, len(remaining))
	for i, p := range remaining {
		result[i] = p.String()
	}
	return result
}

// subtractOne removes excl from base, returning the remaining sub-prefixes.
func subtractOne(base, excl netip.Prefix) []netip.Prefix {
	// If excl fully covers base, nothing remains.
	if excl.Bits() <= base.Bits() && excl.Contains(base.Addr()) {
		return nil
	}
	// If base doesn't overlap excl, keep base.
	if !base.Overlaps(excl) {
		return []netip.Prefix{base}
	}
	// Split base into two halves and recurse.
	if base.Bits() >= 32 && base.Addr().Is4() {
		return nil // can't split further
	}
	if base.Bits() >= 128 && base.Addr().Is6() {
		return nil // can't split further
	}

	left, right := splitPrefix(base)
	var result []netip.Prefix
	result = append(result, subtractOne(left, excl)...)
	result = append(result, subtractOne(right, excl)...)
	return result
}

// splitPrefix splits a prefix into its two child prefixes (one bit longer).
func splitPrefix(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	left := netip.PrefixFrom(p.Addr(), bits)

	// Right half: set the new bit to 1.
	addr := p.Addr()
	var right netip.Prefix
	if addr.Is4() {
		raw := addr.As4()
		byteIdx := (bits - 1) / 8
		bitIdx := 7 - ((bits - 1) % 8)
		raw[byteIdx] |= 1 << bitIdx
		right = netip.PrefixFrom(netip.AddrFrom4(raw), bits)
	} else {
		raw := addr.As16()
		byteIdx := (bits - 1) / 8
		bitIdx := 7 - ((bits - 1) % 8)
		raw[byteIdx] |= 1 << bitIdx
		right = netip.PrefixFrom(netip.AddrFrom16(raw), bits)
	}
	return left, right
}

func dedup(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := ss[:0]
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ============================================================================
// k2b v1 writer (self-contained, matches rule.WriteBundle format)
// ============================================================================

const (
	k2bMagic      = "K2RB"
	k2bVersion    = 2
	k2bHeaderSize = 32
	k2bIndexSize  = 36 // v2: +8 bytes for exclude domains
)

type bundleSet struct {
	Name           string
	Domains        []string
	ExcludeDomains []string // domains to exclude from suffix matching
	CIDRs          []string
}

func writeK2B(path string, sets []bundleSet) error {
	type compiled struct {
		name           []byte
		domainData     []byte
		domainCount    int
		exclDomainData []byte
		exclDomainCnt  int
		ipv4Data       []byte
		ipv4Count      int
		ipv6Data       []byte
		ipv6Count      int
	}

	built := make([]compiled, len(sets))
	for i, s := range sets {
		built[i].name = []byte(s.Name)
		built[i].domainData = buildDomainData(s.Domains)
		built[i].domainCount = len(s.Domains)
		built[i].exclDomainData = buildDomainData(s.ExcludeDomains)
		built[i].exclDomainCnt = len(s.ExcludeDomains)

		v4, v4c := buildIPv4Data(s.CIDRs)
		built[i].ipv4Data = v4
		built[i].ipv4Count = v4c

		v6, v6c := buildIPv6Data(s.CIDRs)
		built[i].ipv6Data = v6
		built[i].ipv6Count = v6c
	}

	// Compute offsets.
	dataStart := uint32(k2bHeaderSize + k2bIndexSize*len(sets))
	offset := dataStart

	type idx struct {
		nameOff, nameLen             uint32
		domainOff, domainCount       uint32
		ipv4Off, ipv4Count           uint32
		ipv6Off, ipv6Count           uint32
		exclDomainOff, exclDomainCnt uint32
	}
	entries := make([]idx, len(sets))

	for i := range built {
		entries[i].nameOff = offset
		entries[i].nameLen = uint32(len(built[i].name))
		offset += uint32(len(built[i].name))
	}
	for i := range built {
		entries[i].domainOff = offset
		entries[i].domainCount = uint32(built[i].domainCount)
		offset += uint32(len(built[i].domainData))
	}
	for i := range built {
		entries[i].ipv4Off = offset
		entries[i].ipv4Count = uint32(built[i].ipv4Count)
		offset += uint32(len(built[i].ipv4Data))
	}
	for i := range built {
		entries[i].ipv6Off = offset
		entries[i].ipv6Count = uint32(built[i].ipv6Count)
		offset += uint32(len(built[i].ipv6Data))
	}
	for i := range built {
		entries[i].exclDomainOff = offset
		entries[i].exclDomainCnt = uint32(built[i].exclDomainCnt)
		offset += uint32(len(built[i].exclDomainData))
	}

	var buf bytes.Buffer

	// Header.
	hdr := make([]byte, k2bHeaderSize)
	copy(hdr[0:4], k2bMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], k2bVersion)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(sets)))
	binary.LittleEndian.PutUint64(hdr[12:20], uint64(time.Now().Unix()))
	buf.Write(hdr)

	// Index (36 bytes per set, v2).
	for i := range entries {
		ib := make([]byte, k2bIndexSize)
		binary.LittleEndian.PutUint32(ib[0:4], entries[i].nameOff)
		binary.LittleEndian.PutUint16(ib[4:6], uint16(entries[i].nameLen))
		binary.LittleEndian.PutUint32(ib[8:12], entries[i].domainOff)
		binary.LittleEndian.PutUint32(ib[12:16], entries[i].domainCount)
		binary.LittleEndian.PutUint32(ib[16:20], entries[i].ipv4Off)
		binary.LittleEndian.PutUint16(ib[20:22], uint16(entries[i].ipv4Count))
		binary.LittleEndian.PutUint32(ib[22:26], entries[i].ipv6Off)
		binary.LittleEndian.PutUint16(ib[26:28], uint16(entries[i].ipv6Count))
		binary.LittleEndian.PutUint32(ib[28:32], entries[i].exclDomainOff)
		binary.LittleEndian.PutUint32(ib[32:36], entries[i].exclDomainCnt)
		buf.Write(ib)
	}

	// Data sections.
	for i := range built {
		buf.Write(built[i].name)
	}
	for i := range built {
		buf.Write(built[i].domainData)
	}
	for i := range built {
		buf.Write(built[i].ipv4Data)
	}
	for i := range built {
		buf.Write(built[i].ipv6Data)
	}
	for i := range built {
		buf.Write(built[i].exclDomainData)
	}

	totalSize := buf.Len()
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return err
	}
	log.Printf("  wrote %s (%d bytes, %d sets)\n", filepath.Base(path), totalSize, len(sets))
	return nil
}

// buildDomainData matches rule.buildDomainData — produces identical binary layout.
func buildDomainData(domains []string) []byte {
	if len(domains) == 0 {
		return nil
	}
	reversed := make([]string, len(domains))
	for i, d := range domains {
		reversed[i] = reverseStr("." + strings.ToLower(d))
	}
	sort.Strings(reversed)

	var strBuf []byte
	offsets := make([]uint32, len(reversed)+1)
	for i, s := range reversed {
		offsets[i] = uint32(len(strBuf))
		strBuf = append(strBuf, []byte(s)...)
	}
	offsets[len(reversed)] = uint32(len(strBuf))

	buf := make([]byte, 4+(len(reversed)+1)*4+len(strBuf))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(reversed)))
	for i, off := range offsets {
		binary.LittleEndian.PutUint32(buf[4+i*4:4+i*4+4], off)
	}
	copy(buf[4+(len(reversed)+1)*4:], strBuf)
	return buf
}

func buildIPv4Data(cidrs []string) ([]byte, int) {
	type r struct{ from, to [4]byte }
	var ranges []r
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		from := p.Masked().Addr().As4()
		to := from
		for i := p.Bits(); i < 32; i++ {
			to[i/8] |= 1 << (7 - i%8)
		}
		ranges = append(ranges, r{from, to})
	}
	sort.Slice(ranges, func(i, j int) bool {
		return bytes.Compare(ranges[i].from[:], ranges[j].from[:]) < 0
	})
	if len(ranges) > 1 {
		merged := ranges[:1]
		for _, cur := range ranges[1:] {
			last := &merged[len(merged)-1]
			if bytes.Compare(cur.from[:], last.to[:]) <= 0 {
				if bytes.Compare(cur.to[:], last.to[:]) > 0 {
					last.to = cur.to
				}
			} else {
				merged = append(merged, cur)
			}
		}
		ranges = merged
	}
	buf := make([]byte, len(ranges)*8)
	for i, rng := range ranges {
		copy(buf[i*8:], rng.from[:])
		copy(buf[i*8+4:], rng.to[:])
	}
	return buf, len(ranges)
}

func buildIPv6Data(cidrs []string) ([]byte, int) {
	type r struct{ from, to [16]byte }
	var ranges []r
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil || !p.Addr().Is6() {
			continue
		}
		from := p.Masked().Addr().As16()
		to := from
		for i := p.Bits(); i < 128; i++ {
			to[i/8] |= 1 << (7 - i%8)
		}
		ranges = append(ranges, r{from, to})
	}
	sort.Slice(ranges, func(i, j int) bool {
		return bytes.Compare(ranges[i].from[:], ranges[j].from[:]) < 0
	})
	if len(ranges) > 1 {
		merged := ranges[:1]
		for _, cur := range ranges[1:] {
			last := &merged[len(merged)-1]
			if bytes.Compare(cur.from[:], last.to[:]) <= 0 {
				if bytes.Compare(cur.to[:], last.to[:]) > 0 {
					last.to = cur.to
				}
			} else {
				merged = append(merged, cur)
			}
		}
		ranges = merged
	}
	buf := make([]byte, len(ranges)*32)
	for i, rng := range ranges {
		copy(buf[i*32:], rng.from[:])
		copy(buf[i*32+16:], rng.to[:])
	}
	return buf, len(ranges)
}

func reverseStr(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// ============================================================================
// Manifest
// ============================================================================

type manifest struct {
	Version string                    `json:"version"`
	Bundles map[string]manifestBundle `json:"bundles"`
}

type manifestBundle struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

func buildManifest(dir string) manifest {
	version := time.Now().Format("2006-01-02")
	m := manifest{
		Version: version,
		Bundles: make(map[string]manifestBundle),
	}
	for _, name := range []string{"overseas.k2b", "cn-direct.k2b"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		h := sha256.Sum256(data)
		key := strings.TrimSuffix(name, ".k2b")
		m.Bundles[key] = manifestBundle{
			Version: version,
			SHA256:  fmt.Sprintf("%x", h),
			Size:    int64(len(data)),
		}
	}
	return m
}
