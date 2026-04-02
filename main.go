// k2-rules-gen compiles domain and IP-CIDR data from open sources into .k2b bundle files.
//
// Usage: go run . [-o output_dir]
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	outDir := flag.String("o", "dist", "output directory")
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

	// Build overseas bundle.
	log.Println("=== building overseas.k2b ===")
	overseasSets, err := buildSets(services, v2flyDir)
	if err != nil {
		log.Fatalf("build overseas: %v", err)
	}
	if err := writeK2B(filepath.Join(*outDir, "overseas.k2b"), overseasSets); err != nil {
		log.Fatalf("write overseas.k2b: %v", err)
	}

	// Build cn-direct bundle.
	log.Println("=== building cn-direct.k2b ===")
	cnSets, err := buildSets(cnServices, v2flyDir)
	if err != nil {
		log.Fatalf("build cn-direct: %v", err)
	}
	if err := writeK2B(filepath.Join(*outDir, "cn-direct.k2b"), cnSets); err != nil {
		log.Fatalf("write cn-direct.k2b: %v", err)
	}

	// Generate manifest.
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

		var domains []string
		for _, name := range svc.V2flyNames {
			d, err := parseV2flyDomains(filepath.Join(v2flyDir, "data", name))
			if err != nil {
				log.Printf("    WARN: v2fly/%s: %v", name, err)
				continue
			}
			domains = append(domains, d...)
			log.Printf("    v2fly/%s: %d domains", name, len(d))
		}

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

		// Deduplicate.
		domains = dedup(domains)
		cidrs = dedup(cidrs)

		log.Printf("  → %s: %d domains, %d CIDRs\n", svc.Name, len(domains), len(cidrs))
		sets = append(sets, bundleSet{
			Name:    svc.Name,
			Domains: domains,
			CIDRs:   cidrs,
		})
	}
	return sets, nil
}

// parseV2flyDomains parses a v2fly domain-list-community data file.
// Format: one domain per line, with optional prefixes (full:, regexp:, keyword:).
// We only take bare entries (suffix match) and full: entries (exact match).
// include: directives are ignored (handled by having multiple V2flyNames per service).
func parseV2flyDomains(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var domains []string
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
		// Strip attributes (@cn, @ads, etc).
		if idx := strings.Index(line, "@"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Handle prefixes.
		switch {
		case strings.HasPrefix(line, "include:"):
			continue // skip includes
		case strings.HasPrefix(line, "regexp:"):
			continue // skip regexps (not supported in k2b)
		case strings.HasPrefix(line, "keyword:"):
			continue // skip keywords (not supported in k2b)
		case strings.HasPrefix(line, "full:"):
			// Exact match — we store as suffix too (same behavior).
			domain := strings.TrimPrefix(line, "full:")
			domains = append(domains, strings.TrimSpace(domain))
		default:
			// Bare entry = suffix match.
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
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
	k2bVersion    = 1
	k2bHeaderSize = 32
	k2bIndexSize  = 28
)

type bundleSet struct {
	Name    string
	Domains []string
	CIDRs   []string
}

func writeK2B(path string, sets []bundleSet) error {
	type compiled struct {
		name        []byte
		domainData  []byte
		domainCount int
		ipv4Data    []byte
		ipv4Count   int
		ipv6Data    []byte
		ipv6Count   int
	}

	built := make([]compiled, len(sets))
	for i, s := range sets {
		built[i].name = []byte(s.Name)
		built[i].domainData = buildDomainData(s.Domains)
		built[i].domainCount = len(s.Domains)

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
		nameOff, nameLen       uint32
		domainOff, domainCount uint32
		ipv4Off, ipv4Count     uint32
		ipv6Off, ipv6Count     uint32
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

	var buf bytes.Buffer

	// Header.
	hdr := make([]byte, k2bHeaderSize)
	copy(hdr[0:4], k2bMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], k2bVersion)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(sets)))
	binary.LittleEndian.PutUint64(hdr[12:20], uint64(time.Now().Unix()))
	buf.Write(hdr)

	// Index.
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
		buf.Write(ib)
	}

	// Data.
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
