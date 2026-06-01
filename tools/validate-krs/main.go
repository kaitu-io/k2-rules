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
	"fmt"
	"os"
	"path/filepath"

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
	fmt.Printf("validate-krs: %d bundle(s) OK\n", len(paths))
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
