// Package krs implements the .krs rule bundle format: writer, reader,
// and runtime match APIs. The format is owned by this package; consumers
// (notably the k2 client) import krs to decode bundles served from CDN.
//
// Wire format details live in CLAUDE.md. Key invariants:
//   - Magic "K2RL", little-endian everywhere except IPv6 byte sequences
//   - Section index is authoritative (file order does not matter)
//   - Unknown section TypeIDs are silently skipped (enum-driven forward-compat)
package krs

// Magic is the 4-byte file signature at offset 0.
const Magic = "K2RL"

// Version is the current writer-emitted format generation. Informational —
// readers do NOT reject on mismatch; forward-compat is via TypeID enum.
const Version uint16 = 2

// Bundle is the in-memory representation of one .krs file.
//
// Writers populate Sets and Apps; reader fills the same fields plus
// internal match-acceleration state on each NamedSet.
type Bundle struct {
	// Version stamped by the writer that produced this bundle.
	// Zero on a freshly constructed Bundle; WriteBundle treats zero
	// as "use the current Version constant".
	Version uint16

	// Sets carries per-set routing rules (domain + IP). Order is
	// preserved through write/read and determines SetTable indices.
	Sets []NamedSet

	// Apps carries flat-region app match patterns. nil means the
	// bundle has no app sections at all (a pure routing bundle).
	Apps *AppPatterns
}

// NamedSet is one named routing set inside a bundle (e.g. "google",
// "youtube"). Routes in the k2 client config reference a NamedSet by Name.
//
// Write inputs (DomainSuffixes/ExcludeDomains/CIDRs) are consumed by
// WriteBundle but NOT populated by ReadBundle — reader leaves them nil
// and instead fills the internal match-acceleration state below.
type NamedSet struct {
	Name string

	// Write inputs — populate before calling WriteBundle.
	DomainSuffixes []string // forward form, e.g. "google.com"
	ExcludeDomains []string // forward form
	CIDRs          []string // e.g. "8.8.8.0/24" or "2001:db8::/32"

	// Read-side internal state — populated by ReadBundle, used by Match*.
	domainSection  domainSection
	excludeSection domainSection
	ipv4           ipRangeSection
	ipv6           ipRangeSection
}

// AppPatterns groups platform-specific app-bypass match data.
type AppPatterns struct {
	Android AndroidPatterns
	Windows WindowsPatterns
	Darwin  DarwinPatterns
}

// AndroidPatterns: Installers do exact-match; Apps support single-* glob.
// Both case-sensitive (Android package names are case-sensitive identifiers).
type AndroidPatterns struct {
	Installers []string
	Apps       []string
}

// WindowsPatterns: glob, lowercased at compile (case-insensitive matching).
type WindowsPatterns struct {
	Apps []string
}

// DarwinPatterns: glob, case-sensitive (macOS process basenames preserve case).
type DarwinPatterns struct {
	Apps []string
}

