package agefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
)

// requirePerm asserts a file exists and carries the given Unix permission bits.
//
// The MODE half is skipped on Windows: Go can only ever report 0666/0444 for a file
// there ($GOROOT/src/os/types_windows.go), so 0600 is not expressible on NTFS. The
// existence half still runs — the stat is deliberately before that early return — so a
// file that was never written still fails on Windows. The production 0600 this guards is
// real and load-bearing on Unix; only the assertion is unavailable here.
func requirePerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

// TestAddResolvesBack: Add writes a new entry that Resolve reads back, and the
// re-encrypted vault still decrypts with the SAME identity (recipient derived from
// the identity, so the file the daemon decrypts on every Resolve is unchanged in
// recipient).
func TestAddResolvesBack(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"EXISTING": "old"})

	b := New(Static{ID: id}, path)
	if err := b.Add("GITHUB_TOKEN", "ghp_new"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := b.Resolve("GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("Resolve after Add: %v", err)
	}
	if got.Value != "ghp_new" {
		t.Fatalf("value = %q, want ghp_new", got.Value)
	}
	// The pre-existing entry must survive an Add (Add modifies the map, not replaces it).
	if g, err := b.Resolve("EXISTING"); err != nil || g.Value != "old" {
		t.Fatalf("EXISTING after Add = %q, %v; want old, nil", g.Value, err)
	}
}

// TestConcurrentAddNoLostUpdate: many concurrent Add calls must all persist. Add is a
// load→modify→write-then-rename sequence; without serialization each writer would rename
// its own snapshot+1 over the file, dropping the others (lost update). The wmu mutex
// serializes them so every entry survives. (The fs-level lost-update is not a Go data
// race, so -race alone wouldn't catch it — this asserts all entries are present.)
func TestConcurrentAddNoLostUpdate(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{})

	b := New(Static{ID: id}, path)
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			if err := b.Add(fmt.Sprintf("K%02d", i), fmt.Sprintf("v%02d", i)); err != nil {
				t.Errorf("Add K%02d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		name := fmt.Sprintf("K%02d", i)
		got, err := b.Resolve(name)
		if err != nil {
			t.Fatalf("%s lost (concurrent Add dropped it): %v", name, err)
		}
		if got.Value != fmt.Sprintf("v%02d", i) {
			t.Fatalf("%s = %q, want v%02d", name, got.Value, i)
		}
	}
}

// TestAddOverwrites: Add to an existing name updates its value.
func TestAddOverwrites(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"K": "v1"})

	b := New(Static{ID: id}, path)
	if err := b.Add("K", "v2"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := b.Resolve("K")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "v2" {
		t.Fatalf("value = %q, want v2", got.Value)
	}
}

// TestRemove: Remove deletes an entry so a subsequent Resolve returns ErrNotFound,
// and a Remove of an absent name returns ErrNotFound (so the caller learns nothing
// was removed rather than a silent no-op).
func TestRemove(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"A": "1", "B": "2"})

	b := New(Static{ID: id}, path)
	if err := b.Remove("A"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := b.Resolve("A"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("Resolve removed A: err = %v, want ErrNotFound", err)
	}
	// The sibling entry must remain.
	if g, err := b.Resolve("B"); err != nil || g.Value != "2" {
		t.Fatalf("B after Remove(A) = %q, %v; want 2, nil", g.Value, err)
	}
	// Removing an absent name reports ErrNotFound.
	if err := b.Remove("MISSING"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("Remove(MISSING) = %v, want ErrNotFound", err)
	}
}

// TestAddIsAtomicNoTempLeftover: a successful Add leaves no ".tmp" sidecar in the
// vault dir (write-then-rename cleans up; rename consumes the temp).
func TestAddIsAtomicNoTempLeftover(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"A": "1"})

	b := New(Static{ID: id}, path)
	if err := b.Add("B", "2"); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

// TestAddFailureLeavesOriginalIntact: if the write cannot complete (the temp path
// is not creatable — its parent dir is read-only), Add returns an error and the
// LIVE vault is byte-for-byte unchanged (write-then-rename never touches the
// original until the atomic rename). This is the corruption-safety invariant.
func TestAddFailureLeavesOriginalIntact(t *testing.T) {
	// Skipped on Windows because the way this test PROVOKES the failure does not work
	// there, not because the invariant is Unix-only. os.Chmod on Windows sets only the
	// read-only attribute, and on a DIRECTORY that attribute does not deny file creation
	// — so "<path>.tmp" is still creatable, Add succeeds, and there is no failed write
	// left to assert about. Denying it for real would need an NTFS DACL, which Go's os
	// package cannot express. The corruption-safety invariant itself is platform-neutral
	// and stays covered on Linux and macOS.
	if runtime.GOOS == "windows" {
		t.Skip("cannot make a directory un-writable via os.Chmod on Windows (NTFS DACLs, not mode bits)")
	}

	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"A": "1"})

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Make the dir read-only so creating "<path>.tmp" fails. The original file
	// already exists and is readable for load(); only the NEW temp create fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	b := New(Static{ID: id}, path)
	if err := b.Add("B", "2"); err == nil {
		t.Fatal("expected Add to fail when temp cannot be created")
	}

	// Restore write perms so we can read the original back for comparison.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("live vault was modified by a failed Add (corruption-safety violated)")
	}
}

// TestVaultMode0600: the re-written vault keeps owner-only permissions.
func TestVaultMode0600(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	writeEncrypted(t, path, id, map[string]string{"A": "1"})

	b := New(Static{ID: id}, path)
	if err := b.Add("B", "2"); err != nil {
		t.Fatal(err)
	}
	requirePerm(t, path, 0o600)
}

// TestAddNonX25519IdentityErrors: Add must derive the recipient from the identity.
// A non-X25519 identity cannot yield an X25519 recipient, so Add must error
// CLEARLY rather than silently writing an unreadable vault.
func TestAddNonX25519IdentityErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	// Seed a valid vault with a real identity so load() succeeds; then point a
	// backend with a NON-X25519 identity at it to isolate the recipient-derivation
	// failure (not a decrypt failure).
	realID, _ := age.GenerateX25519Identity()
	writeEncrypted(t, path, realID, map[string]string{"A": "1"})

	b := New(Static{ID: notX25519{realID}}, path)
	err := b.Add("B", "2")
	if err == nil {
		t.Fatal("expected Add to error for a non-X25519 identity")
	}
	if errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("recipient-derivation failure misreported as ErrNotFound: %v", err)
	}
}

// notX25519 wraps a real identity so load()/decrypt still works (Unwrap delegates),
// but the concrete type is NOT *age.X25519Identity, so the recipient type-assert in
// Add/Remove must fail.
type notX25519 struct{ inner age.Identity }

func (n notX25519) Unwrap(stanzas []*age.Stanza) ([]byte, error) { return n.inner.Unwrap(stanzas) }
