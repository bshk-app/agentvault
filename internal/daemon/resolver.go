package daemon

import (
	"errors"
	"fmt"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/manifest"
)

// ErrBadRequest marks a client-fault resolve error (unknown profile, malformed
// manifest) so the daemon maps it to ipc.CodeBadRequest rather than CodeInternal.
// SECURITY: like every resolver error it carries names/refs only, never a value.
var ErrBadRequest = errors.New("bad request")

// Resolver turns a (profile, manifest bytes) request into resolved name->value pairs,
// authorizing each by tier and recording issued values in the session.
type Resolver struct {
	reg  *backend.Registry
	auth Authorizer
	sess *Session
}

func NewResolver(reg *backend.Registry, auth Authorizer, sess *Session) *Resolver {
	return &Resolver{reg: reg, auth: auth, sess: sess}
}

// Resolve parses the manifest, selects the profile, authorizes + resolves each entry,
// records issued values in the session, and returns name->value. An authorize/resolve
// failure returns (nil, err) — the partial RESULT is never returned to the caller (so
// the daemon maps ErrLocked to CodeLocked). NOTE: it issues to the session per entry as
// it goes, so with the Phase-4 stub (all-or-nothing authz) a failure issues nothing, but
// a future per-secret authorizer could leave earlier entries in the session redactor;
// that is harmless (session values are masking-only, never re-returned).
//
// Phase 5 REQUIREMENT: dangerous-tier (manifest.TierDangerous) must NOT be persisted in
// the session cache ("never cached" per the design). When the real authorizer lands,
// branch on e.Tier here: issue dangerous values only transiently for the single av run,
// not into the TTL'd session.
func (r *Resolver) Resolve(profile string, manifestBytes []byte) (map[string]string, error) {
	m, err := manifest.Parse(manifestBytes)
	if err != nil {
		// A malformed manifest is a client fault, not a daemon fault.
		return nil, fmt.Errorf("%w: manifest: %v", ErrBadRequest, err)
	}
	p, ok := m.Profile(profile)
	if !ok {
		return nil, fmt.Errorf("%w: profile %q not found", ErrBadRequest, profile)
	}
	out := make(map[string]string, len(p))
	for name, e := range p {
		if err := r.auth.Authorize(e.Tier, name); err != nil {
			return nil, err // ErrLocked / denied — issue nothing
		}
		sec, err := r.reg.Resolve(e.Ref)
		if err != nil {
			return nil, fmt.Errorf("resolve %s (%s): %w", name, e.Ref, err)
		}
		out[name] = sec.Value
		r.sess.Issue(name, sec.Value)
	}
	return out, nil
}
