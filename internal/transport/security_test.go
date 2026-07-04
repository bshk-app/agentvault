//go:build !windows

package transport

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSocketAndDirPermissions is the consolidated permission regression at the
// transport.Listen boundary: no other local user may reach the daemon, so the
// socket must be 0600 and its parent dir 0700.
//
// The socket-0600 half overlaps TestListenCreates0600Socket and is kept here so a
// single test pins the full "private endpoint" invariant; the dir-0700 assertion
// is the new coverage (previously only checked indirectly via daemon.New in
// daemon/concurrent_test.go's TestNewCreatesMissingParentDir, not at this boundary).
//
// checkUID foreign-uid rejection is deliberately NOT duplicated here — it is
// already covered by peercred_test.go's TestCheckPeerRejectsOtherUID.
func TestSocketAndDirPermissions(t *testing.T) {
	// Short base under /tmp keeps the path within the macOS 104-byte sun_path limit.
	base, err := os.MkdirTemp("/tmp", "avs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })

	sub := filepath.Join(base, "agentvault")
	path := filepath.Join(sub, "avd.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if fi, err := os.Stat(path); err != nil {
		t.Fatalf("stat socket: %v", err)
	} else if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket perm = %o, want 600", perm)
	}
	if fi, err := os.Stat(sub); err != nil {
		t.Fatalf("stat socket dir: %v", err)
	} else if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("socket dir perm = %o, want 700", perm)
	}
}
