// Package provision creates the local age store for `av setup`: a fresh X25519 identity
// plus an empty age vault. The identity is protected by the best available TIER —
// Secure-Enclave-wrapped (identity.enc) when an Enclave is reachable, otherwise stored in
// the login keychain, with an explicit plaintext (identity.txt) escape hatch. The package
// is linked only by avd, never by the thin av — so both the Wrap step and the keychain
// sink are INJECTED (avd passes enclave.Wrap + keystore.Store; tests pass stubs), keeping
// this package free of the cgo enclave import and the os/exec keystore. SECURITY: the
// identity bytes and vault contents are never logged nor returned in an error — only the
// on-disk paths (or the keychain locator) are. Writes are atomic (temp + fsync + rename)
// so a crash never leaves a partial identity or vault.
package provision

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/config"
)

// Tier names how the generated identity is protected at rest. It is reported back in
// Result so the caller (and `av version`) can announce the chosen protection.
type Tier string

const (
	// TierEnclave wraps the identity in the Secure Enclave (on-disk identity.enc).
	TierEnclave Tier = "enclave"
	// TierKeychain stores the identity in the login keychain (no on-disk identity file).
	TierKeychain Tier = "keychain"
	// TierPlaintext writes the identity unwrapped to identity.txt (the explicit, opt-in
	// escape hatch for hosts without an Enclave or keychain).
	TierPlaintext Tier = "plaintext"
)

// keychainIdentityPath is the synthetic IdentityPath reported for the keychain tier: the
// identity has NO on-disk file, so we surface the keychain locator instead of a path.
const keychainIdentityPath = "keychain:agentvault/identity"

// Options configures a provisioning run. A zero Options provisions the default config dir
// in the auto tier: it tries the Enclave (if Wrap is set) and otherwise the keychain — it
// NEVER auto-selects plaintext.
type Options struct {
	// Dir is the store directory; empty means config.DefaultConfigDir().
	Dir string
	// Rotate forces a fresh identity + empty vault even if a store already exists.
	Rotate bool
	// Tier picks the protection tier; "" means auto (Enclave→keychain, never plaintext).
	Tier Tier
	// RequireEnclave forbids the Enclave→keychain downgrade: with Tier=enclave a Wrap
	// failure becomes a HARD error instead of falling back to the keychain.
	RequireEnclave bool
	// Wrap seals the identity bytes (enclave.Wrap in production, a stub in tests). It is
	// injected so this package needs no enclave import; it may be nil (auto then goes
	// straight to the keychain).
	Wrap func([]byte) ([]byte, error)
	// KeychainStore persists the identity bytes in the login keychain (keystore.Store in
	// production, a recording stub in tests). Required whenever the keychain tier is used.
	KeychainStore func([]byte) error
}

// Result reports the chosen tier, the on-disk paths (or the keychain locator), and whether
// files were created this call. SECURITY: it carries the tier + paths + a bool only —
// never the identity bytes or vault contents.
type Result struct {
	Tier         Tier
	VaultPath    string
	IdentityPath string
	Created      bool
}

// Provision creates (or, when idempotent, reports) the local age store. Behavior:
//   - Resolve the dir (Options.Dir or the config default) and ensure it exists (0700).
//   - IDEMPOTENT: if the vault already exists and !Rotate, return Created:false with the
//     tier INFERRED from what identity exists (identity.enc→enclave, identity.txt→
//     plaintext, else keychain) and touch nothing.
//   - Otherwise generate a fresh X25519 identity ONCE, protect it per the resolved tier,
//     and write an EMPTY age vault encrypted to that identity's recipient. Tier resolution:
//   - auto (default): Wrap success → enclave (identity.enc); ANY wrap error, or a nil
//     Wrap → keychain. NEVER auto-plaintext.
//   - enclave: Wrap failure is a hard error iff RequireEnclave, else it falls back to
//     the keychain (auto-style).
//   - keychain: store via KeychainStore; no on-disk identity file.
//   - plaintext: write identity.txt.
//
// The identity is always written/stored BEFORE the vault, so a failure never leaves a
// vault no reader could open. Both writes are atomic (0600).
func Provision(o Options) (Result, error) {
	dir := o.Dir
	if dir == "" {
		dir = config.DefaultConfigDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{}, fmt.Errorf("create store dir: %w", err)
	}

	vaultPath := filepath.Join(dir, "vault.age")
	encPath := filepath.Join(dir, "identity.enc")
	txtPath := filepath.Join(dir, "identity.txt")

	// Idempotency: a provisioned store (the vault is present) is left untouched unless the
	// caller asks to Rotate. The keychain tier has NO on-disk identity, so the vault is the
	// SSOT for "already provisioned"; the tier is inferred from whichever identity file
	// exists (identity.enc→enclave, identity.txt→plaintext, else keychain).
	if !o.Rotate && fileExists(vaultPath) {
		return Result{
			Tier:         inferTier(encPath, txtPath),
			VaultPath:    vaultPath,
			IdentityPath: inferIdentityPath(encPath, txtPath),
			Created:      false,
		}, nil
	}

	// Generate the identity ONCE; every tier protects these same bytes.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return Result{}, fmt.Errorf("generate identity: %w", err)
	}
	// age.ParseIdentities (the reader on unlock/decrypt) expects newline-terminated lines.
	idBytes := []byte(id.String() + "\n")

	// Protect the identity FIRST (write/store it). If we wrote the vault first and then
	// failed on the identity, the store would have a vault no reader could ever open.
	tier, idPath, err := protectIdentity(o, idBytes, encPath, txtPath)
	if err != nil {
		return Result{}, err
	}

	// Write an EMPTY vault encrypted to the new identity's recipient. We reuse
	// agefile.EncryptVault (SSOT for the vault's on-disk format) and stage it to a temp
	// file, then fsync+rename so the live vault is never partially written.
	if err := writeVaultAtomic(vaultPath, id.Recipient()); err != nil {
		return Result{}, err
	}

	return Result{Tier: tier, VaultPath: vaultPath, IdentityPath: idPath, Created: true}, nil
}

// protectIdentity applies the resolved tier to idBytes and returns the chosen tier plus
// the IdentityPath to report (an on-disk path, or the keychain locator). SECURITY: idBytes
// is passed through to the injected sinks only; it is NEVER logged or embedded in an error.
func protectIdentity(o Options, idBytes []byte, encPath, txtPath string) (Tier, string, error) {
	switch o.Tier {
	case TierPlaintext:
		if err := writeAtomic(txtPath, idBytes); err != nil {
			// SECURITY: the path-only error never includes idBytes.
			return "", "", fmt.Errorf("write identity: %w", err)
		}
		return TierPlaintext, txtPath, nil

	case TierKeychain:
		if err := storeKeychain(o, idBytes); err != nil {
			return "", "", err
		}
		return TierKeychain, keychainIdentityPath, nil

	case TierEnclave:
		// Explicit enclave: try Wrap; on failure, RequireEnclave is what forbids the
		// downgrade — without it we fall back to the keychain (auto-style).
		if blob, werr := tryWrap(o.Wrap, idBytes); werr == nil {
			if err := writeAtomic(encPath, blob); err != nil {
				return "", "", fmt.Errorf("write identity: %w", err)
			}
			return TierEnclave, encPath, nil
		} else if o.RequireEnclave {
			return "", "", fmt.Errorf("wrap identity: %w", werr)
		}
		// Downgrade to keychain.
		if err := storeKeychain(o, idBytes); err != nil {
			return "", "", err
		}
		return TierKeychain, keychainIdentityPath, nil

	default: // auto ("")
		// Enclave when Wrap is set AND succeeds; ANY wrap error (or a nil Wrap) → keychain.
		// NEVER auto-plaintext.
		if o.Wrap != nil {
			if blob, werr := o.Wrap(idBytes); werr == nil {
				if err := writeAtomic(encPath, blob); err != nil {
					return "", "", fmt.Errorf("write identity: %w", err)
				}
				return TierEnclave, encPath, nil
			}
		}
		if err := storeKeychain(o, idBytes); err != nil {
			return "", "", err
		}
		return TierKeychain, keychainIdentityPath, nil
	}
}

// tryWrap requires a non-nil Wrap for the explicit enclave tier and returns its result.
func tryWrap(wrap func([]byte) ([]byte, error), idBytes []byte) ([]byte, error) {
	if wrap == nil {
		return nil, fmt.Errorf("wrap required for the enclave tier")
	}
	return wrap(idBytes)
}

// storeKeychain requires a non-nil KeychainStore and persists the identity through it.
// SECURITY: a store failure is wrapped value-free; idBytes never reaches the error.
func storeKeychain(o Options, idBytes []byte) error {
	if o.KeychainStore == nil {
		return fmt.Errorf("keychain store required for the keychain tier")
	}
	if err := o.KeychainStore(idBytes); err != nil {
		return fmt.Errorf("store identity in keychain: %w", err)
	}
	return nil
}

// inferTier reports the tier of an already-provisioned store from which identity file (if
// any) is on disk: identity.enc→enclave, identity.txt→plaintext, else keychain.
func inferTier(encPath, txtPath string) Tier {
	switch {
	case fileExists(encPath):
		return TierEnclave
	case fileExists(txtPath):
		return TierPlaintext
	default:
		return TierKeychain
	}
}

// inferIdentityPath returns the IdentityPath to report for an already-provisioned store:
// the on-disk identity file when one exists, else the keychain locator.
func inferIdentityPath(encPath, txtPath string) string {
	switch {
	case fileExists(encPath):
		return encPath
	case fileExists(txtPath):
		return txtPath
	default:
		return keychainIdentityPath
	}
}

// fileExists reports whether path is an existing (regular or any) file. A stat error
// other than not-exist is treated as "exists" so we never silently clobber on a transient
// error — Rotate is the explicit way to overwrite.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeAtomic writes data to path via a UNIQUE temp file in the SAME dir (so the rename
// is atomic on one filesystem), fsyncing before the rename and removing the temp on any
// error so a partial file never lingers. The temp name is os.CreateTemp(<base>.tmp-*),
// NOT a fixed "<path>.tmp", so two concurrent `av setup` runs can't truncate each other's
// staging file. Mode is 0600 — the identity is secret material (CreateTemp opens 0600).
func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := os.Chmod(tmp, 0o600); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// writeVaultAtomic encrypts an empty name->value map to a UNIQUE temp file via
// agefile.EncryptVault, fsyncs, then renames it over the vault path (atomic). The temp
// name is os.CreateTemp(<base>.tmp-*), NOT a fixed "<path>.tmp", so two concurrent
// `av setup` runs can't truncate each other's staging vault. On any error before the
// rename it removes the temp so no partial vault is left behind.
// SECURITY: errors carry the path only — never the (empty here) vault contents.
func writeVaultAtomic(vaultPath string, recipient age.Recipient) error {
	f, err := os.CreateTemp(filepath.Dir(vaultPath), filepath.Base(vaultPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp vault: %w", err)
	}
	tmp := f.Name()
	if err := os.Chmod(tmp, 0o600); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("chmod temp vault: %w", err)
	}
	if err := agefile.EncryptVault(f, recipient, map[string]string{}); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("encrypt vault: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync temp vault: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp vault: %w", err)
	}
	if err := os.Rename(tmp, vaultPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename temp vault: %w", err)
	}
	syncDir(filepath.Dir(vaultPath))
	return nil
}

// syncDir best-effort fsyncs a directory so a rename within it is durable across a crash.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
