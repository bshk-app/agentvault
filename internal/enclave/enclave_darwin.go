//go:build darwin && cgo

// Package enclave wraps an age identity with a Secure Enclave key so that even a
// daemon compromise cannot decrypt the file-backend vault without a LIVE Touch ID.
//
// CRYPTO DESIGN (read this before touching the .m file):
//
//	The age identity is an X25519 secret key ("AGE-SECRET-KEY-..."). The Secure
//	Enclave can only generate/hold P-256 (secp256r1) keys, so we CANNOT store the
//	age key IN the Enclave. Instead we WRAP it:
//
//	  1. CREATE: generate a P-256 key pair INSIDE the Secure Enclave
//	     (kSecAttrTokenIDSecureEnclave) whose private key is gated by a
//	     user-presence ACL (kSecAccessControlPrivateKeyUsage |
//	     kSecAccessControlUserPresence). The private key NEVER leaves the Enclave.
//	     The key is persisted in the keychain under a stable tag so subsequent
//	     loads find the same key.
//	  2. WRAP (no Touch ID): encrypt the age identity bytes to the Enclave key's
//	     PUBLIC key with ECIES (kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM).
//	     Encryption uses only the public key, so it needs no presence check. The
//	     ciphertext blob is what we persist on disk (the "wrapped identity").
//	  3. UNWRAP (triggers Touch ID): decrypt the blob with
//	     SecKeyCreateDecryptedData using the Enclave private key. The user-presence
//	     ACL forces a fresh Touch ID before the Enclave will perform the decryption,
//	     returning the original age identity bytes for age.ParseIdentities.
//
// SECURITY: every native call FAILS CLOSED — any Security.framework error returns
// a Go error, never a partial/zeroed result that could be mistaken for plaintext.
// Errors carry an OSStatus code and a generic phrase ONLY; they never embed the
// age identity, the wrapped blob, or any key material.
//
// COMPILE-VERIFIED ONLY: this file links Security.framework and is callable, but
// the real Enclave + Touch ID path can only be exercised on Apple hardware with
// the right entitlements. CI cannot reach it; see enclave_test.go for the guarded
// availability test.
package enclave

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Security -framework Foundation
#include <stdlib.h>

// av_enclave_blob is a heap-allocated output buffer the native side fills. The Go
// side copies out the bytes and then frees `data` with free(). A NULL data with
// len 0 plus a nonzero status means "failure, nothing to free".
typedef struct {
    unsigned char *data;
    int            len;
} av_enclave_blob;

// av_enclave_ensure_key creates-or-loads the Secure Enclave P-256 key under the
// fixed tag. Returns 0 on success; nonzero is an OSStatus-derived failure code.
// No Touch ID: key creation/lookup does not require user presence (only the later
// private-key DECRYPT does). Implemented in enclave_darwin.m.
int av_enclave_ensure_key(void);

// av_enclave_wrap ECIES-encrypts `in`/`in_len` to the Enclave key's PUBLIC key.
// On success returns 0 and fills *out (caller frees out->data). On failure returns
// a nonzero OSStatus-derived code and leaves *out zeroed. NO Touch ID (public-key
// encryption only). Implemented in enclave_darwin.m.
int av_enclave_wrap(const unsigned char *in, int in_len, av_enclave_blob *out);

// av_enclave_unwrap decrypts `in`/`in_len` with the Enclave PRIVATE key. This
// triggers the user-presence ACL -> Touch ID. On success returns 0 and fills *out
// (caller frees out->data). On failure (incl. user cancel/timeout) returns a
// nonzero code and leaves *out zeroed. Implemented in enclave_darwin.m.
int av_enclave_unwrap(const unsigned char *in, int in_len, av_enclave_blob *out);
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// errUnavailable mirrors the non-cgo stub's wording so callers can branch on a
// stable phrase regardless of build. On darwin+cgo it is returned only when the
// Enclave itself cannot be reached (e.g. no hardware/entitlements in CI).
var errUnavailable = errors.New("secure enclave unavailable on this build")

// keyTag is the stable application tag the Enclave key is persisted under. Using a
// fixed tag means EnsureKey is idempotent: the first call creates the key, every
// later call (this boot or a future one) loads the same key so a blob wrapped once
// stays unwrappable. Mirrored verbatim in enclave_darwin.m.
const keyTag = "app.bshk.agentvault.age-wrap"

// EnsureKey creates-or-loads the Secure Enclave P-256 wrapping key. It is safe to
// call repeatedly (idempotent). It performs NO Touch ID — only key material
// management. Returns an error if the Enclave is unreachable (no hardware /
// entitlements), so callers fail closed rather than silently degrade.
//
// SECURITY: the returned error carries only an OSStatus code, never key material.
func EnsureKey() error {
	if rc := C.av_enclave_ensure_key(); rc != 0 {
		return statusError("enclave key create/load", int(rc))
	}
	return nil
}

// Wrap ECIES-encrypts plaintext (the "AGE-SECRET-KEY-..." bytes) to the Enclave
// key's public key and returns the ciphertext blob to persist on disk. It calls
// EnsureKey first so a fresh setup just works. NO Touch ID: encryption uses only
// the public key.
//
// SECURITY: on any failure it returns a nil slice and a value-free error; it never
// returns a partial buffer. The plaintext is never embedded in an error.
func Wrap(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("enclave wrap: empty plaintext")
	}
	if err := EnsureKey(); err != nil {
		return nil, err
	}
	var out C.av_enclave_blob
	rc := C.av_enclave_wrap(
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		C.int(len(plaintext)),
		&out,
	)
	if rc != 0 {
		return nil, statusError("enclave wrap", int(rc))
	}
	return copyAndFree(&out), nil
}

// Unwrap decrypts a wrapped-identity blob with the Enclave private key and returns
// the original age identity bytes. This TRIGGERS the user-presence ACL: a live
// Touch ID (or the configured passcode fallback) must succeed or the Enclave
// refuses to decrypt.
//
// SECURITY: on any failure (incl. user cancel/timeout, or a tampered/foreign blob)
// it returns a nil slice and a value-free error and never a partial/zeroed buffer
// that could be mistaken for plaintext (fail-closed).
func Unwrap(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("enclave unwrap: empty ciphertext")
	}
	var out C.av_enclave_blob
	rc := C.av_enclave_unwrap(
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		C.int(len(ciphertext)),
		&out,
	)
	if rc != 0 {
		return nil, statusError("enclave unwrap", int(rc))
	}
	return copyAndFree(&out), nil
}

// copyAndFree copies the native-allocated blob into a Go-owned slice and frees the
// C buffer. The native side guarantees data/len are consistent on success.
func copyAndFree(out *C.av_enclave_blob) []byte {
	if out.data == nil || out.len <= 0 {
		return nil
	}
	b := C.GoBytes(unsafe.Pointer(out.data), out.len)
	C.free(unsafe.Pointer(out.data))
	out.data = nil
	out.len = 0
	return b
}

// StatusError is the value-free error every failing native call returns. It embeds
// the operation name and the OSStatus-derived numeric code ONLY — never plaintext or
// key material (the Error() text is unchanged from the old fmt.Errorf wording so the
// SECURITY regression test and any log readers stay stable). The Code is exported so
// callers classify a failure WITHOUT string-matching: IsUserCanceled inspects it.
type StatusError struct {
	Op   string
	Code int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s: secure enclave error (OSStatus %d)", e.Op, e.Code)
}

// statusError builds a value-free *StatusError from an OSStatus-derived code.
func statusError(op string, code int) error {
	return &StatusError{Op: op, Code: code}
}

// OSStatus codes we classify as a deliberate user refusal of the Touch ID / passcode
// prompt (as opposed to a hardware/entitlement failure). Values from <Security/SecBase.h>:
//
//	errSecUserCanceled (-128): the user pressed Cancel on the LocalAuthentication sheet.
//	errSecAuthFailed (-25293): authentication failed (e.g. too many failed Touch ID tries
//	then a cancelled passcode) — a denied presence proof, not an unavailable Enclave.
const (
	errSecUserCanceled = -128
	errSecAuthFailed   = -25293
)

// IsUserCanceled reports whether err is an enclave Unwrap failure caused by the user
// DENYING the Touch ID / passcode prompt (cancel / auth-failed), as opposed to an
// Enclave that is simply unreachable. cmd/avd maps a true result to daemon.ErrDenied
// (→ CodeDenied) so a cancelled unlock reads as "denied", while any other failure stays
// CodeLocked. It matches on the structured OSStatus code via errors.As — NEVER on the
// error string — so the classification can't drift if the wording changes.
func IsUserCanceled(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code == errSecUserCanceled || se.Code == errSecAuthFailed
	}
	return false
}
