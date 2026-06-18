// Package backend defines AgentVault's secret-backend interface, the av:// reference
// scheme, and a registry that dispatches references to compiled-in backends. Backend
// IMPLEMENTATIONS live in sub-packages so their dependencies stay out of the thin av.
package backend

// Secret is a resolved secret value. Phase 6 will back Value with memguard-protected
// memory; for now it is a plain string held only transiently.
type Secret struct {
	Value string
}

// Meta is metadata about a secret entry — never the value. Used by List.
type Meta struct {
	Locator string
}

// Backend fetches one secret value by its backend-specific locator (the part of an
// av:// reference after the backend id), and lists metadata only.
type Backend interface {
	Resolve(locator string) (Secret, error)
	List(prefix string) ([]Meta, error)
}
