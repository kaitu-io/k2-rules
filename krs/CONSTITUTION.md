# krs Memory Constitution (binding)

The runtime client path (iOS NE, Android Service, desktop daemon) accesses rule
bundles **only** via `krs.Open` (read-only mmap). The full-expand entry points
`Load` / `LoadNamed` / `ReadBundle` are for the producer pipeline, tooling, and
tests **only** — never the client runtime.

1. **On disk only.** Rule corpus AND all indexes live on disk; runtime access is
   exclusively read-only `mmap` (clean / file-backed pages — reclaimable under
   iOS jetsam `phys_footprint`).
2. **Heap invariant (CI-gated).** A loaded bundle's resident dirty heap is
   `O(set count)`, never `O(rule count)`. Budgets: marginal dirty heap per loaded
   region `< 8 KB`; total rule-attributable dirty heap for any config `< 64 KB`.
3. **Load only what is referenced** (config `match.region` ∪ `overseas`). Never
   the whole corpus.
4. **Never touch the whole mapping** on the constrained path: no full scan,
   `canonicalize`, re-sort, or checksum of a mapped bundle. Trust the producer;
   validate structure at publish time.
5. **Hot path O(1).** Normalize/reverse the query once at the consumer boundary;
   matching allocates a small constant per lookup, never per-set, never per-rule.

Prohibited on the client runtime path: calling `Load`/`LoadNamed`/`ReadBundle`;
holding any `[]string` domain table or `[][]byte` IP table resident; loading an
unreferenced region; silently falling back to full-expand when an index is
missing/corrupt (error instead); pre-faulting the whole mapping.

Rationale: the iOS NE has a hard 50 MB `ActiveHard` jetsam ceiling. Read-only
mmap converts rule data from counted dirty heap into reclaimable clean
file-backed pages — the only way to fit a growing corpus in a fixed budget.
