package backend

import (
	"errors"
	"fmt"
	"sync"
)

// ErrNotFound is returned by a backend when a locator has no value.
var ErrNotFound = errors.New("secret not found")

// Registry dispatches av:// references to registered backends by backend id.
//
// A Registry is SAFE for concurrent use: an RWMutex guards the backends map, so the
// live `setup` provisioner can Register("file", ...) from one goroutine while request
// goroutines call Resolve/List/Writer — the case that arises when `av setup` re-wires
// the file backend on a running daemon.
type Registry struct {
	mu       sync.RWMutex // guards backends against concurrent Register vs Resolve/List/Writer
	backends map[string]Backend
}

func NewRegistry() *Registry {
	return &Registry{backends: map[string]Backend{}}
}

// Register adds a backend under an id (e.g. "file", "1p", "keychain"). It OVERWRITES
// any existing backend under that id (it is a map assignment, not append-only): the
// live `setup` provisioner relies on this to re-wire "file" against a freshly
// provisioned store without a daemon restart. The write lock serializes it against
// concurrent readers (Resolve/List/Writer).
func (r *Registry) Register(id string, b Backend) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backends[id] = b
}

// Resolve parses ref, dispatches to the backend, and returns the secret value.
func (r *Registry) Resolve(ref string) (Secret, error) {
	p, err := ParseRef(ref)
	if err != nil {
		return Secret{}, err
	}
	r.mu.RLock()
	b, ok := r.backends[p.Backend]
	r.mu.RUnlock()
	if !ok {
		return Secret{}, fmt.Errorf("no backend registered for %q", p.Backend)
	}
	return b.Resolve(p.Locator)
}

// List returns metadata (no values) from one backend.
func (r *Registry) List(backendID, prefix string) ([]Meta, error) {
	r.mu.RLock()
	b, ok := r.backends[backendID]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no backend registered for %q", backendID)
	}
	return b.List(prefix)
}

// Backend returns the registered backend under backendID, with ok=false when nothing is
// registered there. It is the READ half of Writer, for the one caller that needs a
// backend as a value rather than a reference to resolve: the daemon builds its SOPS
// identity store over BOTH halves of the local vault, and a Writer alone cannot be read
// through. Resolve stays the way to fetch a single value — this is not a back door around
// it, it returns the same backend Resolve would dispatch to.
func (r *Registry) Backend(backendID string) (Backend, bool) {
	r.mu.RLock()
	b, ok := r.backends[backendID]
	r.mu.RUnlock()
	return b, ok
}

// Writer returns the registered backend under backendID as a Writer, with ok=true
// only if it both exists AND supports writes (implements Writer). A read-only backend
// (1p, keychain) is registered but returns ok=false, so the caller (the "add"/"rm"
// dispatch) can reject the write rather than half-mutate an external store.
func (r *Registry) Writer(backendID string) (Writer, bool) {
	r.mu.RLock()
	b, ok := r.backends[backendID]
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}
	w, ok := b.(Writer)
	return w, ok
}
