package backend

import (
	"sync"
	"testing"
)

// mockBackend is an in-memory backend for tests.
type mockBackend struct{ data map[string]string }

func (m *mockBackend) Resolve(loc string) (Secret, error) {
	v, ok := m.data[loc]
	if !ok {
		return Secret{}, ErrNotFound
	}
	return Secret{Value: v}, nil
}
func (m *mockBackend) List(prefix string) ([]Meta, error) {
	var out []Meta
	for k := range m.data {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			out = append(out, Meta{Locator: k})
		}
	}
	return out, nil
}

func TestRegistryResolve(t *testing.T) {
	r := NewRegistry()
	r.Register("mock", &mockBackend{data: map[string]string{"TOKEN": "s3cr3t"}})

	got, err := r.Resolve("av://mock/TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "s3cr3t" {
		t.Fatalf("value = %q, want s3cr3t", got.Value)
	}
}

func TestRegistryUnknownBackend(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Resolve("av://nope/X"); err == nil {
		t.Fatal("expected error for unregistered backend")
	}
}

// TestRegistryReRegisterOverwrites guards the live-setup re-wire path: registering a
// second backend under an existing id REPLACES the first (map semantics), so `av setup`
// can swap "file" for the freshly provisioned store without a daemon restart.
func TestRegistryReRegisterOverwrites(t *testing.T) {
	r := NewRegistry()
	r.Register("file", &mockBackend{data: map[string]string{"K": "old"}})
	r.Register("file", &mockBackend{data: map[string]string{"K": "new"}})

	got, err := r.Resolve("av://file/K")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "new" {
		t.Fatalf("value = %q, want new (re-register must overwrite)", got.Value)
	}
}

// TestRegistryBackendReturnsTheRegisteredBackend: Backend hands back the very backend
// registered under the id, and reports ok=false for one that was never registered. It
// must also follow a re-register, since the daemon builds its SOPS store through it and
// `av setup` swaps "file" underneath a running daemon.
func TestRegistryBackendReturnsTheRegisteredBackend(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Backend("file"); ok {
		t.Fatal("Backend reported ok for an unregistered id")
	}
	r.Register("file", &mockBackend{data: map[string]string{"K": "old"}})
	r.Register("file", &mockBackend{data: map[string]string{"K": "new"}})

	b, ok := r.Backend("file")
	if !ok {
		t.Fatal("Backend reported not-ok for a registered id")
	}
	got, err := b.Resolve("K")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "new" {
		t.Fatalf("value = %q, want new (Backend must follow a re-register)", got.Value)
	}
}

func TestRegistryListNoValues(t *testing.T) {
	r := NewRegistry()
	r.Register("mock", &mockBackend{data: map[string]string{"A": "1", "B": "2"}})
	metas, err := r.List("mock", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("got %d metas, want 2", len(metas))
	}
	// Meta has no value field — compile-time guarantee values aren't leaked by List.
}

// writableBackend is a mockBackend that also implements Writer, so Registry.Writer
// returns ok=true for it (read-only mockBackend would not exercise the Writer reader).
type writableBackend struct{ mockBackend }

func (w *writableBackend) Add(name, value string) error { return nil }
func (w *writableBackend) Remove(name string) error     { return nil }

// TestRegistryConcurrentRegisterResolve is the regression test for the data race fixed
// by the RWMutex: it hammers Register("file", ...) from many goroutines concurrently
// with Resolve/Writer/List, mirroring the live-`setup` re-wire racing request goroutines.
// Under `go test -race` this FAILS on the old (unguarded-map) Registry and PASSES now.
// It also asserts results stay consistent: Resolve always sees one of the registered
// values (never a torn read) or the not-yet-registered error.
func TestRegistryConcurrentRegisterResolve(t *testing.T) {
	r := NewRegistry()
	// Seed "file" so readers can also hit a present backend, not only the unregistered
	// path; the writers below keep overwriting it (the re-wire that setup performs).
	r.Register("file", &writableBackend{mockBackend{data: map[string]string{"K": "v0"}}})

	const goroutines = 16
	const iters = 200
	var wg sync.WaitGroup

	// Writers: re-register "file" repeatedly (the live-setup re-wire).
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				r.Register("file", &writableBackend{mockBackend{data: map[string]string{"K": "v"}}})
			}
		}(g)
	}

	// Readers: Resolve/List/Writer concurrently with the re-registrations.
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if got, err := r.Resolve("av://file/K"); err != nil {
					t.Errorf("Resolve: %v", err)
				} else if got.Value != "v0" && got.Value != "v" {
					t.Errorf("Resolve value = %q, want v0 or v", got.Value)
				}
				if _, err := r.List("file", ""); err != nil {
					t.Errorf("List: %v", err)
				}
				if _, ok := r.Writer("file"); !ok {
					t.Errorf("Writer(file) = !ok, want a writable backend")
				}
			}
		}()
	}

	wg.Wait()
}
