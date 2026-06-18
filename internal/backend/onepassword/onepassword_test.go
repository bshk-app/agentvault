package onepassword

import (
	"errors"
	"strings"
	"testing"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// mockRunner records the args it was called with and returns canned output/error,
// standing in for the real `op` binary so the resolve logic is fully unit-testable.
type mockRunner struct {
	gotArgs []string
	out     []byte
	err     error
}

func (m *mockRunner) run(args ...string) ([]byte, error) {
	m.gotArgs = args
	return m.out, m.err
}

func TestResolveMapsLocatorToOpRefAndReturnsValue(t *testing.T) {
	// op writes the value to stdout with a trailing newline; Resolve must trim it.
	m := &mockRunner{out: []byte("ghp_value\n")}
	b := NewWithRunner(m.run)

	got, err := b.Resolve("Eng/GitHub CI/token")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "ghp_value" {
		t.Fatalf("value = %q, want %q", got.Value, "ghp_value")
	}

	// The locator (after av://1p/) must map to op://<locator>, passed to `op read`.
	want := []string{"read", "op://Eng/GitHub CI/token"}
	if len(m.gotArgs) != len(want) {
		t.Fatalf("args = %v, want %v", m.gotArgs, want)
	}
	for i := range want {
		if m.gotArgs[i] != want[i] {
			t.Fatalf("args = %v, want %v", m.gotArgs, want)
		}
	}
}

func TestResolveNotFoundMapsToErrNotFound(t *testing.T) {
	// An op-style not-found message must surface as backend.ErrNotFound (errors.Is-able)
	// so a missing secret is never confused with a transport/auth failure.
	m := &mockRunner{err: errors.New(`"op://Eng/Missing/token" isn't an item in any vault`)}
	b := NewWithRunner(m.run)

	_, err := b.Resolve("Eng/Missing/token")
	if !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestResolveGenericErrorIsWrappedWithoutValue(t *testing.T) {
	// A generic op failure must NOT be ErrNotFound (fail-closed: don't drop a secret by
	// reporting "missing"), must be wrapped, and must never leak the value.
	const value = "super-secret-value"
	m := &mockRunner{err: errors.New("could not connect to 1Password desktop app")}
	b := NewWithRunner(m.run)

	_, err := b.Resolve("Eng/GitHub CI/token")
	if err == nil {
		t.Fatal("expected error for generic op failure")
	}
	if errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("generic failure misreported as ErrNotFound: %v", err)
	}
	if strings.Contains(err.Error(), value) {
		t.Fatalf("error leaked the value: %v", err)
	}
	// The ref is helpful and value-free; assert it is present for actionability.
	if !strings.Contains(err.Error(), "op://Eng/GitHub CI/token") {
		t.Fatalf("error should carry the op ref, got: %v", err)
	}
}

func TestListReturnsEmpty(t *testing.T) {
	b := NewWithRunner((&mockRunner{}).run)
	metas, err := b.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 0 {
		t.Fatalf("List returned %d metas, want 0 (metadata-only, not load-bearing)", len(metas))
	}
}

// End-to-end through the registry: a real av://1p/... reference dispatches to this
// backend and returns the value, proving the locator survives ParseRef (slashes +
// spaces) and reaches op:// intact.
func TestRegistryEndToEnd(t *testing.T) {
	m := &mockRunner{out: []byte("ghp_value\n")}
	reg := backend.NewRegistry()
	reg.Register("1p", NewWithRunner(m.run))

	got, err := reg.Resolve("av://1p/Eng/GitHub CI/token")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "ghp_value" {
		t.Fatalf("value = %q, want %q", got.Value, "ghp_value")
	}
	if m.gotArgs[1] != "op://Eng/GitHub CI/token" {
		t.Fatalf("op ref = %q, want op://Eng/GitHub CI/token", m.gotArgs[1])
	}
}
