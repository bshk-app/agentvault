package daemon

import (
	"encoding/json"
	"errors"
	"fmt"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/audit"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/sopsplugin"
)

// sopsStore builds the SOPS identity store over the local vault, or returns a
// ready-to-send rejection. It resolves the backend PER CALL, exactly as "add"/"rm"
// resolve their writer, so a live `av setup` that re-registers the vault is picked up
// without a daemon restart.
//
// Both halves come from sopsplugin.VaultBackendID — the SAME constant the namespace guard
// keys on (sops_namespace.go). That is the whole invariant, and it is why the id is a
// shared symbol rather than a "file" literal in each place: the guard refuses `sops/…`
// for exactly one backend, and this is what makes that backend, by construction, the one
// the Store reads. Constructed over any other, the guard would still pass its own tests
// while `av read <other>/sops/x` printed an age private key.
func (s *Server) sopsStore(id uint64) (*sopsplugin.Store, *ipc.Response) {
	// Writer first: it owns the precise "no local vault — run 'av setup' first" hint for
	// the case that actually happens (a user who never provisioned).
	w, rejection := s.writer(id, sopsplugin.VaultBackendID)
	if rejection != nil {
		return nil, rejection
	}
	b, ok := s.reg.Backend(sopsplugin.VaultBackendID)
	if !ok {
		// Unreachable — the writer lookup just found this id in the same map. Kept
		// because the alternative to a rejection here is a Store with a nil reader.
		r := errResp(id, ipc.CodeInternal, "vault backend not registered")
		return nil, &r
	}
	return sopsplugin.NewStore(b, w), nil
}

// sopsUnwrap serves the "sops_unwrap" RPC. age-plugin-av forwards one file's header
// stanzas; the daemon unwraps them with a stored SOPS identity and returns the per-FILE
// key. The private key never leaves this process, and the reply decrypts exactly one file
// — a compromised `sops` learns one file's key, not every file's.
//
// ORDER IS THE SECURITY DESIGN HERE, not a detail:
//
//  1. parse the params, then the recipient — pure work, so a malformed request is refused
//     for free, regardless of lock state, without costing anyone a Touch ID;
//  2. resolve the vault backend — the same idiom as case "add": a routing fault (no local
//     vault yet) reports its precise hint regardless of lock state;
//  3. open the session (or refuse under NoPrompt);
//  4. identify WHICH stored key the file wants;
//  5. spend a fresh presence check only if that key's tier demands one;
//  6. unwrap.
//
// Step 4 cannot move above step 3, though the plan asked for it. In production the file
// backend's IdentitySource IS the session (cmd/avd/main.go:405), so Store.FindByRecipient
// against a locked session returns ErrLocked rather than an answer: the vault must be
// open before the daemon can know whose key a file wants. The property the ordering
// exists for survives anyway, because ensureUnlocked opens a SESSION rather than
// authorizing one call — a `kustomize build` across a repo full of other teams' secrets
// costs ONE presence check for the whole build, not one per foreign file. And a locked
// NoPrompt caller gets CodeLocked rather than "not yours", which is the honest answer: a
// locked daemon genuinely does not know whose file it is.
func (s *Server) sopsUnwrap(req ipc.Request) ipc.Response {
	var p ipc.SopsUnwrapParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, ipc.CodeBadRequest, err.Error())
	}
	// The recipient is a PUBLIC key carried as its bech32 "age1…" TEXT (base64-of-ASCII
	// once JSON has had it — Go marshals []byte that way). Parsing it here, rather than
	// comparing bytes anywhere, is what makes the encoding impossible to get wrong
	// downstream: Store.FindByRecipient takes the parsed type, so a bytes.Equal against a
	// raw key — which would compare text to bytes and silently never match, reporting
	// every file as "not yours" — cannot be written.
	r, err := age.ParseX25519Recipient(string(p.Recipient))
	if err != nil {
		// A client fault, refused before any vault access and with no presence check.
		// SECURITY: age's parse error is not wrapped — it quotes the offending input, and
		// there is no reason to echo a caller's bytes back at it.
		return errResp(req.ID, ipc.CodeBadRequest, "sops unwrap: recipient is not a valid age recipient")
	}
	store, rejection := s.sopsStore(req.ID)
	if rejection != nil {
		return *rejection
	}
	if rejection := s.ensureUnlockedResp(req.ID, p.NoPrompt); rejection != nil {
		return *rejection
	}
	id, err := store.FindByRecipient(r)
	if err != nil {
		return s.sopsFindError(req.ID, r, err)
	}
	if rejection := s.sopsTierGate(req.ID, id, p.NoPrompt); rejection != nil {
		return *rejection
	}

	stanzas := make([]*age.Stanza, 0, len(p.Stanzas))
	for _, st := range p.Stanzas {
		stanzas = append(stanzas, &age.Stanza{Type: st.Type, Args: st.Args, Body: st.Body})
	}
	// SECURITY: fileKey is a secret. It flows into the response and NOWHERE else — not a
	// log line, not an error, and deliberately not the session either: it is a per-file
	// key, not a user value, so issuing it would park key material in the session cache
	// and the scrub matcher for the whole TTL in order to mask something that never
	// appears in a tool's output.
	fileKey, err := id.Key.Unwrap(stanzas)
	if err != nil {
		code, detail := ipc.CodeInternal, "unwrap failed"
		// SECURITY: id.Name, never id — Identity.String() exists to stop %v from rendering
		// the private key, and reaching past it is exactly the mistake it prevents.
		msg := fmt.Sprintf("sops unwrap %q: the file key could not be unwrapped", id.Name)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			// The stored key matched the recipient we were ASKED for, but no stanza in
			// this file was encrypted to it — a keys.txt pointing at the wrong one of two
			// keys, or stanzas from another file. A client fault, and the file simply
			// stays unreadable.
			code, detail = ipc.CodeBadRequest, "no matching stanza"
			msg = fmt.Sprintf("sops unwrap %q: no stanza in this file was encrypted to it", id.Name)
		}
		s.sopsAudit(id, detail)
		// SECURITY: age's error is NOT wrapped. Its text is secret-free today, but the
		// file key is live in this frame and an error string is the easiest way out.
		return errResp(req.ID, code, msg)
	}
	s.sopsAudit(id, "ok")
	res, _ := json.Marshal(ipc.SopsUnwrapResult{FileKey: fileKey})
	return ipc.Response{ID: req.ID, Result: res}
}

// sopsFindError maps a FindByRecipient failure to a response. The three outcomes are
// deliberately distinct — collapsing them would make a broken vault indistinguishable
// from a file that was never yours, for a key sitting right there.
func (s *Server) sopsFindError(reqID uint64, r *age.X25519Recipient, err error) ipc.Response {
	switch {
	case errors.Is(err, backend.ErrNotFound):
		// The common case in a large repo: a file this vault holds no key for. It costs
		// no presence check (see the ordering note above) and writes NO audit entry —
		// there is no identity to name, and one line per foreign file would drown the log
		// in exactly the situation where the log matters least.
		//
		// SECURITY: the message names the RECIPIENT, which is a public key by
		// construction (design decision 3) and the one datum that tells a user which key
		// the file actually wants.
		return errResp(reqID, ipc.CodeBadRequest,
			fmt.Sprintf("sops unwrap: no stored SOPS identity for recipient %s", r))
	case errors.Is(err, ErrLocked):
		// The session's TTL can expire between the unlock gate and this read.
		return errResp(reqID, ipc.CodeLocked, err.Error())
	default:
		// An entry in the namespace that will not decode, or a vault that will not
		// decrypt. SECURITY: the store's errors name the ENTRY only — store.go's decode
		// never wraps the stored value — so this text is safe to return verbatim.
		return errResp(reqID, ipc.CodeInternal, err.Error())
	}
}

// sopsTierGate applies decision 5's per-identity access policy and returns a
// ready-to-send rejection, or nil to proceed.
//
// normal rides the already-open session: one presence check per COMMAND, which is what
// makes `helm secrets template` over thirty files bearable. dangerous demands a FRESH
// check per call — slow on purpose, so a production deploy is hard to perform
// absent-mindedly.
func (s *Server) sopsTierGate(reqID uint64, id sopsplugin.Identity, noPrompt bool) *ipc.Response {
	if id.Tier != sopsplugin.TierDangerous {
		return nil
	}
	if noPrompt {
		// A caller that has told us no human is present must not be handed a biometric.
		// This is a NARROW divergence from resolver.Resolve, which prompts for a dangerous
		// entry regardless of NoPrompt: resolve runs once per command, this runs once per
		// FILE, so carrying that policy over would hang an agent thirty times instead of
		// once. ErrLocked ("authorization not available") is the honest sentinel — nothing
		// was denied, because nothing was asked — and it hands the agent the same clean
		// exit-69 pause a locked vault does.
		s.sopsAudit(id, "no presence available")
		r := errResp(reqID, ipc.CodeLocked, ErrLocked.Error())
		return &r
	}
	if s.presence == nil {
		r := errResp(reqID, ipc.CodeInternal, "presence not configured")
		return &r
	}
	// SECURITY: the prompt names the identity, never its key.
	if err := s.presence.Prompt(fmt.Sprintf("Decrypt a SOPS file with %q", id.Name)); err != nil {
		// Kind "denied" is the resolver's vocabulary for a refused dangerous touch; one
		// grep collects every denial in the log regardless of which RPC asked.
		s.audit.Log(audit.Event{Kind: "denied", Name: id.Name, Tier: string(id.Tier), Detail: "sops unwrap"})
		r := errResp(reqID, ipc.CodeDenied, ErrDenied.Error())
		return &r
	}
	return nil
}

// sopsAudit records ONE entry per unwrap that reached an identity: which identity, at
// which tier, and how it went.
//
// SECURITY (structural): audit.Event has no value field, so nothing here CAN carry key
// material — but the arguments still matter. It takes the whole Identity and reads only
// Name and Tier from it, so every call site is spared the chance to pass id.Key.
func (s *Server) sopsAudit(id sopsplugin.Identity, outcome string) {
	s.audit.Log(audit.Event{Kind: "sops_unwrap", Name: id.Name, Tier: string(id.Tier), Detail: outcome})
}
