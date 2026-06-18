package daemon

import (
	"errors"
	"os"

	"github.com/beshkenadze/agentvault/internal/manifest"
)

// ErrLocked means the daemon cannot authorize a secret issuance (no auth configured,
// or session locked). Maps to ipc.CodeLocked.
var ErrLocked = errors.New("vault locked: authorization not available")

// Authorizer decides whether a secret of a given tier may be issued now. Phase 5
// provides the Touch ID implementation; Phase 4 ships only the test stub.
type Authorizer interface {
	Authorize(tier manifest.Tier, name string) error
}

// stubAuthorizer authorizes iff AV_TEST_AUTH=allow is set in the daemon's environment.
// It exists so the Phase 4 pipeline is end-to-end testable before Touch ID lands.
type stubAuthorizer struct{}

func NewStubAuthorizer() Authorizer { return stubAuthorizer{} }

func (stubAuthorizer) Authorize(_ manifest.Tier, _ string) error {
	if os.Getenv("AV_TEST_AUTH") == "allow" {
		return nil
	}
	return ErrLocked
}
