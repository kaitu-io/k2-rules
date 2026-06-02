// validate-krs is the publish-time structural gate for .krs bundles. It asserts
// every generated bundle opens through the runtime mmap path (krs.Open) AND the
// heap reader (krs.ReadBundle), and that the two agree on set names. Exits 1 on
// any failure so a structurally-broken or index-less artifact can never reach
// the CDN.
//
// The constitution forbids a full validating scan on the client runtime path and
// instead mandates "validate structure at publish time" — this is that step.
// Open is the load-bearing check: it fails loud on a domain payload missing its
// offset-index section, so a Version-1 / pre-index bundle is rejected here rather
// than crashing or mis-routing a client that fetched it.
//
// Run from repo root after generating bundles:
//
//	go run ./tools/validate-krs dist
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kaitu-io/k2-rules/krs"
)

func main() {
	dir := "dist"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.krs"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "validate-krs:", err)
		os.Exit(1)
	}
	if len(paths) == 0 {
		fmt.Fprintf(os.Stderr, "validate-krs: no .krs files found in %s\n", dir)
		os.Exit(1)
	}
	failed := 0
	for _, p := range paths {
		if err := validateFile(p); err != nil {
			fmt.Printf("FAIL %s: %v\n", filepath.Base(p), err)
			failed++
			continue
		}
		fmt.Printf("ok   %s\n", filepath.Base(p))
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "validate-krs: %d/%d bundle(s) failed structural validation\n",
			failed, len(paths))
		os.Exit(1)
	}
	if err := checkRuleFloor(dir, loadPrevCounts(os.Getenv("PREV_MANIFEST"))); err != nil {
		fmt.Fprintln(os.Stderr, "validate-krs:", err)
		os.Exit(1)
	}
	fmt.Printf("validate-krs: %d bundle(s) OK\n", len(paths))
}

// criticalRegions must never regress sharply — a silent rule collapse here
// degrades a whole region to all-proxy (the incident class this gate guards).
var criticalRegions = []string{"cn"}

// regressionFloorPct: a critical region's new ruleCount must be at least this
// percent of its previous manifest value.
const regressionFloorPct = 80

// checkRuleFloor opens every *.krs in dir and enforces: (1) ruleCount > 0 for
// all; (2) each critical region >= regressionFloorPct% of prevCounts[region]
// (when a previous count is known). prevCounts may be nil (first release).
func checkRuleFloor(dir string, prevCounts map[string]int) error {
	paths, err := filepath.Glob(filepath.Join(dir, "*.krs"))
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		b, err := krs.ReadBundle(data)
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
		region := strings.TrimSuffix(filepath.Base(p), ".krs")
		n := b.RuleCount()
		if n == 0 {
			return fmt.Errorf("%s: 0 rules — empty bundle would route the region to all-proxy", region)
		}
		counts[region] = n
	}
	for _, region := range criticalRegions {
		prev, ok := prevCounts[region]
		if !ok || prev == 0 {
			continue
		}
		cur := counts[region]
		if cur*100 < prev*regressionFloorPct {
			return fmt.Errorf("%s: ruleCount regressed %d → %d (< %d%% of previous)",
				region, prev, cur, regressionFloorPct)
		}
	}
	return nil
}

// loadPrevCounts reads ruleCount per region from a previous manifest.json path
// (env PREV_MANIFEST, set by CI from the prior release). Missing/unreadable →
// nil (no regression check on first release, or when the prior manifest predates
// the ruleCount field).
func loadPrevCounts(path string) map[string]int {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m struct {
		Bundles map[string]struct {
			RuleCount int `json:"ruleCount"`
		} `json:"bundles"`
	}
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	out := map[string]int{}
	for k, v := range m.Bundles {
		out[k] = v.RuleCount
	}
	return out
}

// validateFile opens path through both readers and cross-checks them. Returns a
// descriptive error on any structural problem; nil when the bundle is sound.
func validateFile(path string) error {
	db, err := krs.Open(path)
	if err != nil {
		return fmt.Errorf("mmap Open (runtime path): %w", err)
	}
	defer db.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	heap, err := krs.ReadBundle(data)
	if err != nil {
		return fmt.Errorf("heap ReadBundle: %w", err)
	}

	disk := db.SetNames()
	if len(disk) != len(heap.Sets) {
		return fmt.Errorf("set count mismatch: mmap=%d heap=%d", len(disk), len(heap.Sets))
	}
	for i, name := range disk {
		if heap.Sets[i].Name != name {
			return fmt.Errorf("set[%d] name mismatch: mmap=%q heap=%q", i, name, heap.Sets[i].Name)
		}
	}
	return nil
}
