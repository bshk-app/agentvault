package backend

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned by a backend when a locator has no value.
var ErrNotFound = errors.New("secret not found")

// Registry dispatches av:// references to registered backends by backend id.
type Registry struct {
	backends map[string]Backend
}

func NewRegistry() *Registry {
	return &Registry{backends: map[string]Backend{}}
}

// Register adds a backend under an id (e.g. "file", "1p", "keychain").
func (r *Registry) Register(id string, b Backend) {
	r.backends[id] = b
}

// Resolve parses ref, dispatches to the backend, and returns the secret value.
func (r *Registry) Resolve(ref string) (Secret, error) {
	p, err := ParseRef(ref)
	if err != nil {
		return Secret{}, err
	}
	b, ok := r.backends[p.Backend]
	if !ok {
		return Secret{}, fmt.Errorf("no backend registered for %q", p.Backend)
	}
	return b.Resolve(p.Locator)
}

// List returns metadata (no values) from one backend.
func (r *Registry) List(backendID, prefix string) ([]Meta, error) {
	b, ok := r.backends[backendID]
	if !ok {
		return nil, fmt.Errorf("no backend registered for %q", backendID)
	}
	return b.List(prefix)
}
