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
	if rejection := s.sopsEnsureUnlocked(req.ID, "unwrap", p.NoPrompt); rejection != nil {
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
		// NEITHER outcome below is a daemon fault. id.Key was parsed out of the store before
		// this line, so the only input that varies here is p.Stanzas: age refuses because the
		// header it was handed does not fit the key, never because the daemon is broken.
		// Reporting a truncated SOPS header as CodeInternal ("the daemon broke") sends a user
		// looking in the wrong place, and it lets any client mint an internal error at will.
		// CodeInternal on this RPC stays for the genuine daemon faults ABOVE — an unregistered
		// vault, a store entry that will not decode — which no request can provoke.
		//
		// They differ in the one way a CALLER can act on, which is why they differ by CODE
		// and not merely by wording. The default is the ORDINARY outcome of a keys.txt with
		// more than one AgentVault pointer in it: the stored key matched the recipient we were
		// ASKED for, but no stanza in this file was encrypted to it, because the file belongs
		// to the user's OTHER key. That is "try the next identity", so it is CodeNoMatch —
		// age-plugin-av turns it into age.ErrIncorrectIdentity and age moves on. Sent as
		// CodeBadRequest it aborted the whole decrypt, and a two-key keys.txt could not read
		// files encrypted to the second key at all.
		//
		// SECURITY: id.Name, never id — Identity.String() exists to stop %v from rendering
		// the private key, and reaching past it is exactly the mistake it prevents.
		code := ipc.CodeNoMatch
		detail := "no matching stanza"
		msg := fmt.Sprintf("sops unwrap %q: no stanza in this file was encrypted to it", id.Name)
		if !errors.Is(err, age.ErrIncorrectIdentity) {
			// Not "the wrong key" but "not a stanza": an arg that is not base64, a
			// recipient block of the wrong length, a body that cannot hold a file key
			// (age's x25519.go:166-192). A truncated header reads exactly like this.
			// It stays CodeBadRequest — and so stays a HARD error — because trying the next
			// identity cannot fix a header that is not a header, and falling through would
			// bury a corrupt file under age's generic "no identity matched".
			code = ipc.CodeBadRequest
			detail = "malformed stanza"
			msg = fmt.Sprintf("sops unwrap %q: the file's header stanzas are malformed", id.Name)
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
		// This vault holds no key under the recipient the CALLER named. Unlike the unwrap
		// failure below it says nothing about the file: the recipient comes from the
		// keys.txt line, not from the header, so this outcome is a property of the pointer
		// and is the same for every file the caller tries. It costs no presence check (see
		// the ordering note above) and writes NO audit entry — there is no identity to name.
		//
		// CodeNoMatch, so a keys.txt holding a stale AgentVault pointer beside a live one
		// still decrypts through the live one instead of aborting on the stale one. The
		// COST of that is real and is accepted deliberately: when EVERY pointer is stale,
		// this message no longer reaches the user — age reports its generic "no identity
		// matched" instead. `av sops ls` is the recovery, and Task 12 documents it.
		//
		// SECURITY: the message names the RECIPIENT, which is a public key by
		// construction (design decision 3) and the one datum that tells a user which key
		// the file actually wants.
		return errResp(reqID, ipc.CodeNoMatch,
			fmt.Sprintf("sops unwrap: no stored SOPS identity for recipient %s", r))
	case errors.Is(err, ErrLocked):
		// The session's TTL can expire between the unlock gate and this read. Same
		// situation as the gate, so the same actionable text.
		return errResp(reqID, ipc.CodeLocked, sopsLockedMsg("unwrap"))
	default:
		// An entry in the namespace that will not decode, or a vault that will not
		// decrypt. SECURITY: the store's errors name the ENTRY only — store.go's decode
		// never wraps the stored value — so this text is safe to return verbatim.
		return errResp(reqID, ipc.CodeInternal, err.Error())
	}
}

// sopsLockedMsg is what a genuinely locked vault says on the SOPS path, and it is bespoke
// for one reason: this is the only path whose message reaches a human unedited.
//
// ErrLocked's own text — "vault locked: authorization not available" — is accurate and
// says nothing about what to do next. Everywhere else that does not matter, because
// cmd/av maps CodeLocked to its own actionable string (main.go:402) and the human reads
// that one. Here the reader is whoever ran `sops`/`helm secrets`, the text arrives via
// age-plugin-av, and Task 8 established that the plugin must RELAY rather than invent —
// so if the advice is not in this string it reaches nobody. Hence it is added here rather
// than by widening ErrLocked, which other paths and their tests depend on.
//
// "ask a human" is deliberate: the caller that sees this set no_prompt, which means it is
// an agent, and an agent cannot answer a Touch ID. That holds for the management RPCs too
// — nothing but an agent reaches this text with no_prompt set. It must also stay DIFFERENT
// from sopsTierGate's message — that pairing is what stops one substituted string from
// satisfying two situations that need opposite responses.
//
// op names the operation that was refused and is a PARAMETER rather than the word "unwrap"
// baked in, because `av sops keygen` against a locked vault reporting "sops unwrap: vault
// locked" names something that never happened. A per-operation subject was chosen over one
// generic subject ("sops:") so a log line still says which call was refused; the advice
// after the colon is identical because it is identical — every one of them is fixed by
// `av unlock`.
//
// The word is the SUBCOMMAND's, not the RPC method's: "unwrap", "keygen", "import", "ls",
// "rm" — so sops_put says "import" and sops_list says "ls". Every message on this path can
// end up in front of the person who typed the command, and naming the RPC would have them
// searching their terminal history for an `av sops put` they never ran. Audit Kinds go the
// other way (sops_put) because their reader is a machine grepping for one RPC.
func sopsLockedMsg(op string) string {
	return fmt.Sprintf(`sops %s: vault locked — ask a human to run "av unlock"`, op)
}

// sopsEnsureUnlocked is ensureUnlockedResp with the SOPS path's own locked-vault wording.
// It defers to the shared gate for the decision and the CodeDenied case (a refused Touch
// ID is the same event on every RPC) and rewrites only the CodeLocked message, naming op
// (see sopsLockedMsg).
func (s *Server) sopsEnsureUnlocked(reqID uint64, op string, noPrompt bool) *ipc.Response {
	rejection := s.ensureUnlockedResp(reqID, noPrompt)
	if rejection == nil || rejection.Error == nil || rejection.Error.Code != ipc.CodeLocked {
		return rejection
	}
	r := errResp(reqID, ipc.CodeLocked, sopsLockedMsg(op))
	return &r
}

// sopsTierGate applies decision 5's per-identity access policy and returns a
// ready-to-send rejection, or nil to proceed.
//
// normal rides the already-open session: one presence check per COMMAND, which is what
// makes `helm secrets template` over thirty files bearable. dangerous demands a FRESH
// check per call — slow on purpose, so a production deploy is hard to perform
// absent-mindedly.
//
// The row that is easy to miss when reading "one check per file": the FIRST dangerous file
// met while the vault is LOCKED costs TWO — the unwrap that opens the session (step 3),
// then this one. They are not the same check charged twice. The first buys a session that
// every later file rides for free; the second is the per-file one this tier is for, and
// skipping it because a session happens to be fresh would mean the first dangerous file of
// the day is the one that never prompts. It matches `av run` on a dangerous entry from a
// locked vault, which costs the same two.
func (s *Server) sopsTierGate(reqID uint64, id sopsplugin.Identity, noPrompt bool) *ipc.Response {
	if id.Tier != sopsplugin.TierDangerous {
		return nil
	}
	if noPrompt {
		// A caller that has told us no human is present must not be handed a biometric.
		// This is a NARROW divergence from resolver.Resolve, which prompts for a dangerous
		// entry regardless of NoPrompt: resolve runs once per command, this runs once per
		// FILE, so carrying that policy over would hang an agent thirty times instead of
		// once. CodeLocked is the honest code — nothing was denied, because nothing was
		// asked — and it hands the agent the same clean exit-69 pause a locked vault does.
		s.sopsAudit(id, "no presence available")
		// The MESSAGE, however, is deliberately not ErrLocked's "vault locked". The vault
		// is not locked here: the session is open (step 3 saw to that) and only the fresh
		// per-file check is missing. "vault locked" would send a human to `av unlock`,
		// which changes nothing on this path, and the agent's retry would fail identically
		// — a loop. So it names what is actually missing. age-plugin-av must relay this
		// text rather than substitute one of its own (Task 8), because it is the last layer
		// that can still tell the two CodeLocked situations apart.
		r := errResp(reqID, ipc.CodeLocked, fmt.Sprintf(
			"sops unwrap %q: dangerous-tier identity needs a fresh presence check, and this caller set no_prompt",
			id.Name))
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
//
// outcome is drawn from a CLOSED set of literals, and sopsAuditDetails in sops_rpc_test.go
// restates it: a new outcome must be added there too, deliberately. That allowlist is the
// leak assertion — a Detail built from anything but a literal is caught by it whatever
// encoding the accident used, which no test for base64 or hex can promise.
func (s *Server) sopsAudit(id sopsplugin.Identity, outcome string) {
	s.audit.Log(audit.Event{Kind: "sops_unwrap", Name: id.Name, Tier: string(id.Tier), Detail: outcome})
}
