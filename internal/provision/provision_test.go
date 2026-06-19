package provision

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// stubWrap is an injected Wrap that prefixes its input, so the provision tests need no
// real Secure Enclave: it stands in for enclave.Wrap (which avd injects in production).
// It must be reversible enough for the test to assert the wrapped blob is NOT plaintext.
func stubWrap(in []byte) ([]byte, error) { return append([]byte("WRAP:"), in...), nil }

// fileMode returns the file's permission bits (the 0o600 we require for both the
// identity and the vault), failing the test if the file is missing.
func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestProvisionWrapped: with an injected Wrap and the default (auto) tier, Provision
// writes identity.enc + vault.age (both 0600) under the temp dir, returns Created:true
// with Tier=enclave, and the wrapped identity file is NOT the plaintext identity (it went
// through Wrap). We can't decrypt the wrapped case without an unwrap, so we assert files
// exist + modes + that wrap was applied.
func TestProvisionWrapped(t *testing.T) {
	dir := t.TempDir()
	r, err := Provision(Options{Dir: dir, Wrap: stubWrap})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !r.Created {
		t.Fatal("Created = false, want true on first provision")
	}
	if r.Tier != TierEnclave {
		t.Fatalf("Tier = %q, want %q", r.Tier, TierEnclave)
	}
	encPath := filepath.Join(dir, "identity.enc")
	vaultPath := filepath.Join(dir, "vault.age")
	if r.IdentityPath != encPath {
		t.Fatalf("IdentityPath = %q, want %q", r.IdentityPath, encPath)
	}
	if r.VaultPath != vaultPath {
		t.Fatalf("VaultPath = %q, want %q", r.VaultPath, vaultPath)
	}
	if m := fileMode(t, encPath); m != 0o600 {
		t.Fatalf("identity.enc mode = %o, want 600", m)
	}
	if m := fileMode(t, vaultPath); m != 0o600 {
		t.Fatalf("vault.age mode = %o, want 600", m)
	}
	// The identity must have gone through Wrap: the on-disk blob starts with our marker.
	blob, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, []byte("WRAP:")) {
		t.Fatalf("identity.enc was not wrapped (prefix missing)")
	}
	// A plaintext identity.txt must NOT exist in the wrapped path.
	if _, err := os.Stat(filepath.Join(dir, "identity.txt")); !os.IsNotExist(err) {
		t.Fatalf("identity.txt should not exist in wrapped mode, stat err = %v", err)
	}
}

// TestProvisionAutoFallbackToKeychain: in the default (auto) tier, when Wrap FAILS, the
// generated identity falls back to the keychain — KeychainStore receives the identity
// bytes, NO identity.enc is left on disk, and Result.Tier is keychain (NEVER plaintext).
func TestProvisionAutoFallbackToKeychain(t *testing.T) {
	dir := t.TempDir()
	failWrap := func([]byte) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
	var stored []byte
	keychainStore := func(id []byte) error {
		stored = append([]byte(nil), id...) // copy: the caller may reuse the slice
		return nil
	}

	r, err := Provision(Options{Dir: dir, Wrap: failWrap, KeychainStore: keychainStore})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if r.Tier != TierKeychain {
		t.Fatalf("Tier = %q, want %q (auto-fallback)", r.Tier, TierKeychain)
	}
	if r.IdentityPath != keychainIdentityPath {
		t.Fatalf("IdentityPath = %q, want %q", r.IdentityPath, keychainIdentityPath)
	}
	// KeychainStore must have received the identity (a parseable age identity line).
	if len(stored) == 0 {
		t.Fatal("KeychainStore did not receive the identity")
	}
	if _, perr := age.ParseIdentities(bytes.NewReader(stored)); perr != nil {
		t.Fatalf("KeychainStore got non-identity bytes: %v", perr)
	}
	// No on-disk identity file in either form.
	if _, err := os.Stat(filepath.Join(dir, "identity.enc")); !os.IsNotExist(err) {
		t.Fatalf("identity.enc should not exist after keychain fallback, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.txt")); !os.IsNotExist(err) {
		t.Fatalf("identity.txt should not exist after keychain fallback, stat err = %v", err)
	}
	// The vault is still written.
	if m := fileMode(t, r.VaultPath); m != 0o600 {
		t.Fatalf("vault.age mode = %o, want 600", m)
	}
}

// TestProvisionAutoNoWrapToKeychain: auto tier with Wrap==nil goes straight to keychain
// (no enclave attempt). It must NEVER auto-write a plaintext identity.
func TestProvisionAutoNoWrapToKeychain(t *testing.T) {
	dir := t.TempDir()
	var stored []byte
	r, err := Provision(Options{Dir: dir, KeychainStore: func(id []byte) error {
		stored = append([]byte(nil), id...)
		return nil
	}})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if r.Tier != TierKeychain {
		t.Fatalf("Tier = %q, want %q", r.Tier, TierKeychain)
	}
	if len(stored) == 0 {
		t.Fatal("KeychainStore did not receive the identity")
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.txt")); !os.IsNotExist(err) {
		t.Fatalf("identity.txt must not be auto-written, stat err = %v", err)
	}
}

// TestProvisionRequireEnclaveHardError: Tier=enclave + RequireEnclave + a failing Wrap is
// a HARD error (no downgrade), and leaves no vault/identity behind.
func TestProvisionRequireEnclaveHardError(t *testing.T) {
	dir := t.TempDir()
	failWrap := func([]byte) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
	keychainCalled := false
	r, err := Provision(Options{
		Dir:            dir,
		Tier:           TierEnclave,
		RequireEnclave: true,
		Wrap:           failWrap,
		KeychainStore:  func([]byte) error { keychainCalled = true; return nil },
	})
	if err == nil {
		t.Fatalf("expected a hard error when RequireEnclave and Wrap fails, got Result %+v", r)
	}
	if keychainCalled {
		t.Fatal("KeychainStore was called despite RequireEnclave (downgrade is forbidden)")
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.age")); !os.IsNotExist(err) {
		t.Fatalf("vault.age should not be written on a hard enclave error, stat err = %v", err)
	}
}

// TestProvisionEnclaveDowngrades: Tier=enclave WITHOUT RequireEnclave falls back to
// keychain (auto-style) when Wrap fails — it is RequireEnclave that forbids downgrade.
func TestProvisionEnclaveDowngrades(t *testing.T) {
	dir := t.TempDir()
	failWrap := func([]byte) ([]byte, error) { return nil, io.ErrUnexpectedEOF }
	var stored []byte
	r, err := Provision(Options{
		Dir:           dir,
		Tier:          TierEnclave,
		Wrap:          failWrap,
		KeychainStore: func(id []byte) error { stored = append([]byte(nil), id...); return nil },
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if r.Tier != TierKeychain {
		t.Fatalf("Tier = %q, want %q (downgrade allowed without RequireEnclave)", r.Tier, TierKeychain)
	}
	if len(stored) == 0 {
		t.Fatal("KeychainStore did not receive the identity on downgrade")
	}
}

// TestProvisionExplicitKeychain: Tier=keychain stores the generated identity via
// KeychainStore, writes the vault, and writes NO on-disk identity file.
func TestProvisionExplicitKeychain(t *testing.T) {
	dir := t.TempDir()
	var stored []byte
	r, err := Provision(Options{
		Dir:           dir,
		Tier:          TierKeychain,
		KeychainStore: func(id []byte) error { stored = append([]byte(nil), id...); return nil },
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if r.Tier != TierKeychain {
		t.Fatalf("Tier = %q, want %q", r.Tier, TierKeychain)
	}
	if r.IdentityPath != keychainIdentityPath {
		t.Fatalf("IdentityPath = %q, want %q", r.IdentityPath, keychainIdentityPath)
	}
	if len(stored) == 0 {
		t.Fatal("KeychainStore did not receive the identity")
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.enc")); !os.IsNotExist(err) {
		t.Fatalf("identity.enc should not exist for keychain tier, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.txt")); !os.IsNotExist(err) {
		t.Fatalf("identity.txt should not exist for keychain tier, stat err = %v", err)
	}
	if m := fileMode(t, r.VaultPath); m != 0o600 {
		t.Fatalf("vault.age mode = %o, want 600", m)
	}
}

// TestProvisionKeychainRequiresStore: Tier=keychain with a nil KeychainStore errors
// clearly rather than dropping the identity, and leaves no vault behind.
func TestProvisionKeychainRequiresStore(t *testing.T) {
	dir := t.TempDir()
	if _, err := Provision(Options{Dir: dir, Tier: TierKeychain}); err == nil {
		t.Fatal("expected an error when KeychainStore is nil for the keychain tier")
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.age")); !os.IsNotExist(err) {
		t.Fatalf("vault.age should not be written when KeychainStore is missing, stat err = %v", err)
	}
}

// TestProvisionPlaintext: Tier=plaintext writes identity.txt (no Wrap applied, no
// identity.enc) and the vault decrypts to an empty JSON map with the on-disk identity.
func TestProvisionPlaintext(t *testing.T) {
	dir := t.TempDir()
	// Wrap is non-nil but must NOT be called in plaintext mode (proves no wrap path).
	wrapCalled := false
	r, err := Provision(Options{Dir: dir, Tier: TierPlaintext, Wrap: func(b []byte) ([]byte, error) {
		wrapCalled = true
		return b, nil
	}})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if wrapCalled {
		t.Fatal("Wrap was called in plaintext mode, want it skipped")
	}
	if r.Tier != TierPlaintext {
		t.Fatalf("Tier = %q, want %q", r.Tier, TierPlaintext)
	}
	txtPath := filepath.Join(dir, "identity.txt")
	if r.IdentityPath != txtPath {
		t.Fatalf("IdentityPath = %q, want %q", r.IdentityPath, txtPath)
	}
	if m := fileMode(t, txtPath); m != 0o600 {
		t.Fatalf("identity.txt mode = %o, want 600", m)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.enc")); !os.IsNotExist(err) {
		t.Fatalf("identity.enc should not exist in plaintext mode, stat err = %v", err)
	}

	// The produced vault must decrypt to an empty map with the generated identity.
	idBytes, err := os.ReadFile(txtPath)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := age.ParseIdentities(strings.NewReader(string(idBytes)))
	if err != nil {
		t.Fatalf("parse identity.txt: %v", err)
	}
	vf, err := os.Open(r.VaultPath)
	if err != nil {
		t.Fatal(err)
	}
	defer vf.Close()
	dr, err := age.Decrypt(vf, ids...)
	if err != nil {
		t.Fatalf("decrypt vault: %v", err)
	}
	plain, err := io.ReadAll(dr)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(plain)); got != "{}" {
		t.Fatalf("vault plaintext = %q, want %q", got, "{}")
	}
}

// TestProvisionIdempotent: a second Provision with an existing enclave store (and !Rotate)
// returns Created:false with the inferred Tier and leaves BOTH files byte-for-byte
// unchanged.
func TestProvisionIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := Provision(Options{Dir: dir, Wrap: stubWrap}); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	encPath := filepath.Join(dir, "identity.enc")
	vaultPath := filepath.Join(dir, "vault.age")
	encBefore, _ := os.ReadFile(encPath)
	vaultBefore, _ := os.ReadFile(vaultPath)

	r, err := Provision(Options{Dir: dir, Wrap: stubWrap})
	if err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	if r.Created {
		t.Fatal("Created = true on idempotent re-run, want false")
	}
	if r.Tier != TierEnclave {
		t.Fatalf("inferred Tier = %q, want %q (identity.enc present)", r.Tier, TierEnclave)
	}
	encAfter, _ := os.ReadFile(encPath)
	vaultAfter, _ := os.ReadFile(vaultPath)
	if !bytes.Equal(encBefore, encAfter) {
		t.Fatal("identity.enc changed on idempotent re-run")
	}
	if !bytes.Equal(vaultBefore, vaultAfter) {
		t.Fatal("vault.age changed on idempotent re-run")
	}
}

// TestProvisionIdempotentKeychain: with only a vault on disk (no identity file, the
// keychain tier's shape), an idempotent re-run reports Created:false and Tier=keychain
// WITHOUT touching the keychain store.
func TestProvisionIdempotentKeychain(t *testing.T) {
	dir := t.TempDir()
	if _, err := Provision(Options{
		Dir:           dir,
		Tier:          TierKeychain,
		KeychainStore: func([]byte) error { return nil },
	}); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	keychainCalled := false
	r, err := Provision(Options{
		Dir:           dir,
		Tier:          TierKeychain,
		KeychainStore: func([]byte) error { keychainCalled = true; return nil },
	})
	if err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	if r.Created {
		t.Fatal("Created = true on idempotent keychain re-run, want false")
	}
	if r.Tier != TierKeychain {
		t.Fatalf("inferred Tier = %q, want %q (no identity file present)", r.Tier, TierKeychain)
	}
	if keychainCalled {
		t.Fatal("KeychainStore was called on an idempotent re-run, want it skipped")
	}
}

// TestProvisionRotate: Rotate:true regenerates the identity even when a store exists,
// so the identity bytes change (and a fresh empty vault is written).
func TestProvisionRotate(t *testing.T) {
	dir := t.TempDir()
	if _, err := Provision(Options{Dir: dir, Wrap: stubWrap}); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	encPath := filepath.Join(dir, "identity.enc")
	encBefore, _ := os.ReadFile(encPath)

	r, err := Provision(Options{Dir: dir, Rotate: true, Wrap: stubWrap})
	if err != nil {
		t.Fatalf("rotate Provision: %v", err)
	}
	if !r.Created {
		t.Fatal("Created = false on rotate, want true")
	}
	encAfter, _ := os.ReadFile(encPath)
	if bytes.Equal(encBefore, encAfter) {
		t.Fatal("identity.enc unchanged after Rotate, want a fresh identity")
	}
}
