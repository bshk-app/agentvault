package transport

import (
	"path/filepath"
	"testing"
)

// TestDefaultSocketPathOverride: $AV_SOCKET_PATH wins over the platform default, on
// EVERY platform. This is the contract the isolated-instance story rests on — `av` and
// `avd` both resolve their endpoint through DefaultSocketPath, so one variable is enough
// to put them on a private endpoint together. Deliberately not build-tagged: the whole
// point is that Windows behaves like Unix here, and the Windows default (%LOCALAPPDATA%)
// shares no environment variable with the Unix one.
func TestDefaultSocketPathOverride(t *testing.T) {
	want := filepath.Join(t.TempDir(), "avd.sock")
	t.Setenv(SocketPathEnv, want)

	got, err := DefaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("path = %q, want the override %q", got, want)
	}
}

// TestDefaultSocketPathEmptyOverrideIgnored: an empty AV_SOCKET_PATH is "unset", not
// "use the empty path". Without this an exported-but-empty variable in a shell profile
// would send the daemon to bind whatever "" resolves to.
func TestDefaultSocketPathEmptyOverrideIgnored(t *testing.T) {
	t.Setenv(SocketPathEnv, "")

	got, err := DefaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("empty override must fall through to the platform default, got empty path")
	}
}
