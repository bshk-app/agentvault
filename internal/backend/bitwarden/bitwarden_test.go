package bitwarden

import (
	"errors"
	"strings"
	"testing"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// mockRunner records the args it was called with and returns canned output/error,
// standing in for the real `bw` binary so resolve logic stays unit-testable.
type mockRunner struct {
	gotArgs []string
	out     []byte
	err     error
	calls   int
}

func (m *mockRunner) run(args ...string) ([]byte, error) {
	m.calls++
	m.gotArgs = args
	return m.out, m.err
}

func TestResolvePasswordMapsLocatorToBwGetAndReturnsValue(t *testing.T) {
	m := &mockRunner{out: []byte("ghp_value\n")}
	b := NewWithRunner(m.run)

	got, err := b.Resolve("password/GitHub")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "ghp_value" {
		t.Fatalf("value = %q, want %q", got.Value, "ghp_value")
	}

	want := []string{"get", "password", "GitHub", "--raw", "--nointeraction"}
	assertArgs(t, m.gotArgs, want)
}

func TestResolveTargetMayContainSlashes(t *testing.T) {
	m := &mockRunner{out: []byte("nested-value\n")}
	b := NewWithRunner(m.run)

	got, err := b.Resolve("password/Folder/GitHub")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "nested-value" {
		t.Fatalf("value = %q, want nested-value", got.Value)
	}

	want := []string{"get", "password", "Folder/GitHub", "--raw", "--nointeraction"}
	assertArgs(t, m.gotArgs, want)
}

func TestResolveAllowedObjects(t *testing.T) {
	for _, object := range []string{"password", "username", "uri", "totp", "notes"} {
		t.Run(object, func(t *testing.T) {
			m := &mockRunner{out: []byte("value\n")}
			b := NewWithRunner(m.run)

			got, err := b.Resolve(object + "/GitHub")
			if err != nil {
				t.Fatal(err)
			}
			if got.Value != "value" {
				t.Fatalf("value = %q, want value", got.Value)
			}

			want := []string{"get", object, "GitHub", "--raw", "--nointeraction"}
			assertArgs(t, m.gotArgs, want)
		})
	}
}

func TestMalformedLocatorDoesNotInvokeRunner(t *testing.T) {
	for _, locator := range []string{"", "password", "/GitHub", "password/"} {
		t.Run(locator, func(t *testing.T) {
			m := &mockRunner{}
			b := NewWithRunner(m.run)

			_, err := b.Resolve(locator)
			if err == nil {
				t.Fatal("expected malformed locator error")
			}
			if m.calls != 0 {
				t.Fatalf("runner called %d times for malformed locator", m.calls)
			}
		})
	}
}

func TestItemLocatorRejectedWithoutInvokingRunner(t *testing.T) {
	m := &mockRunner{}
	b := NewWithRunner(m.run)

	_, err := b.Resolve("item/GitHub")
	if err == nil {
		t.Fatal("expected item locator to be rejected")
	}
	if m.calls != 0 {
		t.Fatalf("runner called %d times for unsupported item locator", m.calls)
	}
	if !strings.Contains(err.Error(), "unsupported object") {
		t.Fatalf("err = %v, want unsupported object", err)
	}
}

func TestResolveNotFoundMapsToErrNotFound(t *testing.T) {
	m := &mockRunner{err: errors.New("Not found.")}
	b := NewWithRunner(m.run)

	_, err := b.Resolve("password/Missing")
	if !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestResolveGenericErrorIsWrappedWithoutValue(t *testing.T) {
	const value = "super-secret-value"
	for _, msg := range []string{
		"You are not logged in.",
		"Vault is locked.",
		"More than one result was found. Try getting your item by id.",
		"getaddrinfo ENOTFOUND vault.example.invalid",
		"host not found.",
	} {
		t.Run(msg, func(t *testing.T) {
			m := &mockRunner{err: errors.New(msg)}
			b := NewWithRunner(m.run)

			_, err := b.Resolve("password/GitHub")
			if err == nil {
				t.Fatal("expected generic bw failure")
			}
			if errors.Is(err, backend.ErrNotFound) {
				t.Fatalf("generic failure misreported as ErrNotFound: %v", err)
			}
			if strings.Contains(err.Error(), value) {
				t.Fatalf("error leaked the value: %v", err)
			}
			if !strings.Contains(err.Error(), "bw get password GitHub") {
				t.Fatalf("error should carry value-free bw context, got: %v", err)
			}
		})
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

func TestRegistryEndToEnd(t *testing.T) {
	m := &mockRunner{out: []byte("ghp_value\n")}
	reg := backend.NewRegistry()
	reg.Register("bw", NewWithRunner(m.run))

	got, err := reg.Resolve("av://bw/password/GitHub")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "ghp_value" {
		t.Fatalf("value = %q, want ghp_value", got.Value)
	}

	want := []string{"get", "password", "GitHub", "--raw", "--nointeraction"}
	assertArgs(t, m.gotArgs, want)
}

func assertArgs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args = %v, want %v", got, want)
		}
	}
}
