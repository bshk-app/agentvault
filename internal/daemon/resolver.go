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
// authorizing each via presence and recording issued values in the session.
type Resolver struct {
	reg      *backend.Registry
	presence Presence
	sess     *Session
}

func NewResolver(reg *backend.Registry, presence Presence, sess *Session) *Resolver {
	return &Resolver{reg: reg, presence: presence, sess: sess}
}

// Resolve parses the manifest, selects the profile, applies the per-tier access policy
// to each entry, and returns name->value for the single av run. On any failure it
// returns (nil, err) — a partial result is NEVER returned (so the daemon maps the
// sentinel to the right code and the caller injects nothing). SECURITY: every error
// carries names/refs only, never a value.
//
// Per-tier policy (design decisions #2/#3):
//
//   - normal: requires an already-unlocked session (the agent runs `av unlock` once,
//     which fires presence; normal-tier resolve NEVER prompts mid-run). If the session
//     is locked -> ErrLocked (the agent asks a human to unlock). The value is returned
//     AND issued into the session, so it is CACHED for the unlock TTL and masked by the
//     scrub layers.
//
//   - dangerous: requires a FRESH presence check per secret (Touch ID in production).
//     On denial -> ErrDenied. The value is returned for the single command but is
//     DELIBERATELY NOT issued into the session — dangerous values are NEVER cached.
//
// Consequence of never-cached (accepted tradeoff): a dangerous value is masked at
// layer 1 (the resolver hands it to `av run`, which redacts the child's stdout against
// the values it injected for that run) but is NOT exact-matched by the layer-2 scrub
// service, because the session redactor/matcher only know cached (normal-tier) values.
// gitleaks-on-scrub (deferred to Phase 6) is the only layer-2 net for dangerous values.
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
		switch e.Tier {
		case manifest.TierNormal:
			// Served from an open session; never prompts mid-run.
			if r.sess.Locked() {
				return nil, ErrLocked
			}
		case manifest.TierDangerous:
			// Fresh presence per dangerous secret; never cached.
			if err := r.presence.Prompt(fmt.Sprintf("Allow %q to use %s", profile, name)); err != nil {
				return nil, ErrDenied
			}
		default:
			// manifest.validate() rejects unknown tiers, but guard anyway: a bad tier
			// is a client fault, reported by name only (never a value).
			return nil, fmt.Errorf("%w: entry %q: unknown tier", ErrBadRequest, name)
		}

		sec, err := r.reg.Resolve(e.Ref)
		if err != nil {
			return nil, fmt.Errorf("resolve %s (%s): %w", name, e.Ref, err)
		}
		out[name] = sec.Value
		if e.Tier == manifest.TierNormal {
			r.sess.Issue(name, sec.Value) // cache normal-tier only; dangerous is NEVER issued
		}
	}
	return out, nil
}
