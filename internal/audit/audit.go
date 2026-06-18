// Package audit is AgentVault's append-only audit log of dangerous touches: every
// issuance, unlock, lock, rate-limit alert, and denied access produces ONE JSONL
// entry. SECURITY (structural): an Event carries names/tiers/profiles/reasons ONLY —
// there is NO value field, so a secret value can never be written here by construction.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Event is one audit entry. The fields are metadata ONLY (names, tiers, profiles,
// reasons). There is DELIBERATELY no value field: the no-secret guarantee is
// structural, not just convention, so no caller can ever record a secret value.
type Event struct {
	Time    string `json:"time"`
	Kind    string `json:"kind"`              // issue | unlock | lock | alert | denied
	Name    string `json:"name,omitempty"`    // logical secret name (never the value)
	Tier    string `json:"tier,omitempty"`    // normal | dangerous
	Profile string `json:"profile,omitempty"` // av run profile
	Detail  string `json:"detail,omitempty"`  // secret-free reason (e.g. rate-limit text)
}

// Logger is the audit sink the daemon injects. Tests use a buffer-backed logger; the
// real daemon uses a FileLogger. The default is NopLogger so existing behavior is
// unchanged until a real logger is wired.
type Logger interface {
	Log(Event)
}

// NopLogger discards every event. It is the default sink (audit off) so existing
// tests and call sites need no change.
type NopLogger struct{}

// Log discards the event.
func (NopLogger) Log(Event) {}

// FileLogger appends events as JSONL to a single file. It is concurrency-safe (a
// mutex serializes appends) and opens the file O_APPEND|O_CREATE|O_WRONLY at mode
// 0600, so the log is append-only and never world-readable.
type FileLogger struct {
	mu  sync.Mutex
	f   *os.File
	now func() time.Time // injectable clock for deterministic tests
}

// NewFileLogger opens (or creates) the audit log at path in append mode, mode 0600.
// The parent directory must already exist (the daemon creates the user dir alongside
// the socket). It uses the wall clock; tests inject one via the now field.
func NewFileLogger(path string) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &FileLogger{f: f, now: time.Now}, nil
}

// Log appends ONE JSONL line for the event. If the event carries no Time, the
// logger stamps it from its clock. A marshal/write error is dropped on purpose:
// audit must never break the issuance path, and there is no value to leak.
func (l *FileLogger) Log(e Event) {
	if e.Time == "" {
		e.Time = l.now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(line)
}

// Close closes the underlying file.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
