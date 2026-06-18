package daemon

import (
	"errors"
	"log"
	"sync"
)

// errMlockUnsupported is returned by mlock on platforms with no swap-pinning syscall.
var errMlockUnsupported = errors.New("mlock unsupported on this platform")

// mlockWarnOnce makes the RLIMIT_MEMLOCK / unsupported-platform warning fire at most
// once per process: a fallback per issued value would spam the log without adding
// signal.
var mlockWarnOnce sync.Once

// lockedValue is the at-rest container for one session secret value (memguard-style).
// It holds the bytes in a Go-heap []byte and, on creation, mlocks the backing pages so
// the secret never reaches swap. Destroy() ZEROIZES the bytes (overwrite with zeros)
// then munlocks. String() returns a transient cleartext copy for the redactor.
//
// Go's GC is non-moving for heap allocations, so mlock on a []byte's backing array is
// valid: the pages do not move under the kernel pin for the buffer's lifetime.
//
// Mlock failure (commonly RLIMIT_MEMLOCK on an unprivileged process) MUST NOT break
// brokering: newLockedValue falls back to a non-mlocked-but-still-zeroized buffer and
// logs once. Confidentiality of the at-rest value is reduced (it may swap) but the
// zeroize-on-lock/expiry guarantee is preserved.
type lockedValue struct {
	mu     sync.Mutex
	buf    []byte // backing bytes; len 0 after Destroy
	locked bool   // true if mlock succeeded (so Destroy munlocks)
}

// newLockedValue copies v's bytes into a protected buffer, mlocks them (best-effort),
// and returns it. The input string is left untouched (Go strings are immutable); the
// copy is what gets pinned and later zeroized.
func newLockedValue(v string) *lockedValue {
	lv := &lockedValue{buf: []byte(v)}
	if len(lv.buf) > 0 {
		if err := mlock(lv.buf); err != nil {
			mlockWarnOnce.Do(func() {
				log.Printf("agentvault: mlock unavailable (%v); session secrets are zeroized on lock but may swap. Raise RLIMIT_MEMLOCK to enable no-swap protection.", err)
			})
		} else {
			lv.locked = true
		}
	}
	return lv
}

// String returns a transient cleartext copy of the protected value for the redactor to
// build its masking forms. The returned string is normal (swappable, GC-managed) Go
// memory — this is the DOCUMENTED limitation: the masker needs cleartext to match, so
// the canonical at-rest value is protected but the transient form handed to the
// matcher is not. Returns "" after Destroy.
func (lv *lockedValue) String() string {
	lv.mu.Lock()
	defer lv.mu.Unlock()
	return string(lv.buf)
}

// Destroy zeroizes the backing bytes (overwrite with zeros) and munlocks them. Safe to
// call more than once; subsequent calls are no-ops. After Destroy the value is gone —
// String() returns "".
func (lv *lockedValue) Destroy() {
	lv.mu.Lock()
	defer lv.mu.Unlock()
	if lv.buf == nil {
		return
	}
	for i := range lv.buf {
		lv.buf[i] = 0
	}
	if lv.locked {
		_ = munlock(lv.buf) // best-effort; failure is non-fatal (we already zeroized)
		lv.locked = false
	}
	lv.buf = nil
}

// bytesForTest exposes the backing bytes for zeroize assertions in tests. It returns
// the live slice header captured before Destroy nils it; tests capture a buffer
// reference before Lock and inspect these bytes afterward.
func (lv *lockedValue) bytesForTest() []byte {
	lv.mu.Lock()
	defer lv.mu.Unlock()
	return lv.buf
}
