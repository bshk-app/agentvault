package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/audit"
	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/sopsplugin"
)

// This file is the management half of the SOPS surface — the four RPCs behind
// `av sops keygen | import | ls | rm`. sops_unwrap next door serves age-plugin-av on every
// encrypted file; these serve a human at a terminal, a handful of times ever.
//
// They are RPCs for the same reason `av setup` is one (cmd/av/main.go:608): generating,
// parsing and encoding age keys lives in sopsplugin, sopsplugin imports filippo.io/age, and
// TestAvStaysThin (cmd/av/deps_test.go) forbids av linking either. So av sends names and
// ferries opaque strings, and every decision that needs to understand a key is made here.
//
// The consequence worth stating once: each reply carries the ready-made AGE-PLUGIN-AV-1…
// pointer (ipc.SopsIdentityInfo.Identity), because `av sops import` must write that line
// into the user's keys.txt and av cannot compute it. The daemon renders it; av writes bytes
// it never has to understand.
//
// ORDERING is the same in all four, and it is `case "add"`'s (server.go:527):
//
//  1. unmarshal, then validate whatever is pure input — a request that was always going to
//     be refused must not cost a Touch ID, and an agent must not be told "locked" (and sent
//     to retry an identical broken request forever) when its name or tier is the problem;
//  2. resolve the vault backend, so a config fault ("no local vault — run 'av setup'
//     first") reports precisely regardless of lock state;
//  3. open the session, or refuse under NoPrompt;
//  4. act.

// sopsKeygen serves "sops_keygen": generate a NEW SOPS identity, store it under the given
// name and tier, and return its public half.
//
// SECURITY: the private key is generated inside avd, goes straight into the vault, and
// NEVER appears in the reply — SopsIdentityInfo has no field that could hold it. This is
// the one path on which a SOPS private key never exists outside this process at all, which
// is why it is the recommended way to make a key rather than `age-keygen | av sops import`.
func (s *Server) sopsKeygen(req ipc.Request) ipc.Response {
	var p ipc.SopsKeygenParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, ipc.CodeBadRequest, err.Error())
	}
	tier, rejection := sopsValidate(req.ID, p.Name, p.Tier)
	if rejection != nil {
		return *rejection
	}
	store, rejection := s.sopsStore(req.ID)
	if rejection != nil {
		return *rejection
	}
	if rejection := s.sopsEnsureUnlocked(req.ID, "keygen", p.NoPrompt); rejection != nil {
		return *rejection
	}
	// Generated AFTER the gates on purpose: a request that gets refused should not have
	// minted key material at all, however briefly.
	key, err := age.GenerateX25519Identity()
	if err != nil {
		// SECURITY: age's error is not wrapped. It cannot carry a key today (the only
		// failure is the entropy source), and a half-made identity is live in this frame.
		return errResp(req.ID, ipc.CodeInternal, "sops keygen: could not generate an identity")
	}
	if err := store.Put(p.Name, key, tier); err != nil {
		return sopsStoreError(req.ID, "keygen", p.Name, err)
	}
	s.sopsManageAudit("sops_keygen", p.Name, tier)
	return sopsIdentityResponse(req.ID, p.Name, tier, key.Recipient())
}

// sopsPut serves "sops_put": store an EXISTING age private key under a name — the daemon
// half of `av sops import`, which sends one call per key it found in the user's keys.txt.
//
// SECURITY: p.Value is the private key, and this is the ONLY RPC on the SOPS surface that
// takes key material in. It is treated exactly as AddParams.Value: it flows into
// age.ParseX25519Identity and from there into the vault, and reaches no log, no audit entry
// and no error string — including the parse failure below, which names the identity rather
// than echoing what the caller sent.
func (s *Server) sopsPut(req ipc.Request) ipc.Response {
	var p ipc.SopsPutParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, ipc.CodeBadRequest, err.Error())
	}
	tier, rejection := sopsValidate(req.ID, p.Name, p.Tier)
	if rejection != nil {
		return *rejection
	}
	// Parsed here, before any vault access, for the same reason sops_unwrap parses its
	// recipient first: a value that is not a key is a client fault and costs nothing to
	// refuse. TrimSpace because the value comes off a line of keys.txt and a trailing
	// newline is the likeliest artefact of reading one — the same tolerance store.decode
	// grants a hand-edited entry.
	key, err := age.ParseX25519Identity(strings.TrimSpace(string(p.Value)))
	if err != nil {
		// SECURITY: age's error is NOT wrapped and p.Value is NOT echoed. age quotes the
		// offending input on some paths, and the offending input here is a private key.
		return errResp(req.ID, ipc.CodeBadRequest,
			fmt.Sprintf("sops import %q: the value is not an age private key (want AGE-SECRET-KEY-1…)", p.Name))
	}
	store, rejection := s.sopsStore(req.ID)
	if rejection != nil {
		return *rejection
	}
	if rejection := s.sopsEnsureUnlocked(req.ID, "import", p.NoPrompt); rejection != nil {
		return *rejection
	}
	if err := store.Put(p.Name, key, tier); err != nil {
		return sopsStoreError(req.ID, "import", p.Name, err)
	}
	s.sopsManageAudit("sops_put", p.Name, tier)
	return sopsIdentityResponse(req.ID, p.Name, tier, key.Recipient())
}

// sopsList serves "sops_list": every stored identity, name, tier, recipient and pointer.
//
// It gates on the session like the others because listing genuinely reads the vault: the
// recipients are derived from the stored keys rather than from a public index, so a locked
// vault has nothing to list.
//
// SECURITY: the reply is built from sopsplugin.Info — which has no key field — into
// SopsIdentityInfo, which has none either. Two structs stand between `av sops ls` output
// and a private key, and neither has anywhere to put one.
func (s *Server) sopsList(req ipc.Request) ipc.Response {
	var p ipc.SopsListParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, ipc.CodeBadRequest, err.Error())
	}
	store, rejection := s.sopsStore(req.ID)
	if rejection != nil {
		return *rejection
	}
	if rejection := s.sopsEnsureUnlocked(req.ID, "ls", p.NoPrompt); rejection != nil {
		return *rejection
	}
	infos, err := store.List()
	if err != nil {
		// Store.List is STRICT about a corrupt entry where FindByRecipient tolerates one
		// (store.go's each): this is the diagnostic surface, so an entry that will not
		// decode must be reported rather than silently missing from the listing a user
		// consults precisely because something is wrong.
		//
		// The empty name is not a placeholder: a listing names no single identity, and the
		// only branch that would print one (ErrNotFound) is unreachable from List — a
		// namespace with nothing in it lists as empty, not as missing.
		return sopsStoreError(req.ID, "ls", "", err)
	}
	out := make([]ipc.SopsIdentityInfo, 0, len(infos))
	for _, info := range infos {
		// Re-parsed rather than passed as text: EncodeIdentity takes the typed recipient,
		// which is the one place the pointer's payload format is decided. This cannot fail
		// for a value List produced (it is Recipient().String()), so a failure means the
		// store returned something impossible — report it, do not print a broken pointer.
		r, err := age.ParseX25519Recipient(info.Recipient)
		if err != nil {
			return errResp(req.ID, ipc.CodeInternal,
				fmt.Sprintf("sops ls %q: stored entry has no usable recipient", info.Name))
		}
		out = append(out, sopsIdentityInfo(info.Name, info.Tier, r))
	}
	res, _ := json.Marshal(ipc.SopsListResult{Identities: out})
	return ipc.Response{ID: req.ID, Result: res}
}

// sopsRm serves "sops_rm": delete one stored identity.
//
// The daemon just removes, exactly as `case "rm"` does. The "this destroys the only copy of
// a key that files are encrypted to" confirmation is `av sops rm`'s job: a TTY prompt has no
// meaning on this side of a socket, and putting the guard here would not make the daemon
// safer — it would only make the CLI's guard look optional.
//
// The name is deliberately NOT run through sopsplugin.ValidateName. This RPC is the only
// way to delete anything under sops/ — `av rm sops/x` is refused by the namespace guard
// (sops_namespace.go) — so it must be able to clear an entry ValidateName would reject:
// junk written by hand, or by any `av add` that predates that guard. Refusing those names
// here would leave a corrupt entry that breaks `av sops ls` with no way to remove it.
func (s *Server) sopsRm(req ipc.Request) ipc.Response {
	var p ipc.SopsRmParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, ipc.CodeBadRequest, err.Error())
	}
	store, rejection := s.sopsStore(req.ID)
	if rejection != nil {
		return *rejection
	}
	if rejection := s.sopsEnsureUnlocked(req.ID, "rm", p.NoPrompt); rejection != nil {
		return *rejection
	}
	if err := store.Remove(p.Name); err != nil {
		return sopsStoreError(req.ID, "rm", p.Name, err)
	}
	// Tier is left empty: Remove does not read the entry, and guessing one would put a
	// value in the log that was never checked against what was deleted.
	s.sopsManageAudit("sops_rm", p.Name, "")
	ok, _ := json.Marshal("ok")
	return ipc.Response{ID: req.ID, Result: ok}
}

// sopsValidate checks the two fields a management request can get wrong on its own — the
// name and the tier — and returns the normalized tier or a ready-to-send rejection.
//
// Both rules come from sopsplugin so there is one definition of a valid identity: Store.Put
// enforces the same two at the vault. Running them HERE, ahead of the backend lookup and
// the unlock gate, is what makes a typo cost nothing (see the ordering note at the top).
func sopsValidate(reqID uint64, name, tier string) (sopsplugin.Tier, *ipc.Response) {
	if err := sopsplugin.ValidateName(name); err != nil {
		r := errResp(reqID, ipc.CodeBadRequest, err.Error())
		return "", &r
	}
	t, err := sopsplugin.NormalizeTier(sopsplugin.Tier(tier))
	if err != nil {
		// The store's text names the offending tier and nothing else.
		r := errResp(reqID, ipc.CodeBadRequest, fmt.Sprintf("sops identity %q: %v", name, err))
		return "", &r
	}
	return t, nil
}

// sopsIdentityInfo renders one identity for the wire: its name, its tier, its PUBLIC
// recipient, and the AGE-PLUGIN-AV-1… pointer that recipient encodes to.
//
// It is the single place a reply about an identity is built, and it takes the recipient —
// never the *age.X25519Identity — so no call site can hand it a private key to render.
func sopsIdentityInfo(name string, tier sopsplugin.Tier, r *age.X25519Recipient) ipc.SopsIdentityInfo {
	return ipc.SopsIdentityInfo{
		Name:      name,
		Tier:      string(tier),
		Recipient: r.String(),
		Identity:  sopsplugin.EncodeIdentity(r),
	}
}

// sopsIdentityResponse is the successful reply shared by keygen and put.
func sopsIdentityResponse(reqID uint64, name string, tier sopsplugin.Tier, r *age.X25519Recipient) ipc.Response {
	res, _ := json.Marshal(sopsIdentityInfo(name, tier, r))
	return ipc.Response{ID: reqID, Result: res}
}

// sopsStoreError maps a Store failure on the management path to a response, mirroring
// sopsFindError's three-way split so a broken vault never looks like a mistyped name.
//
// SECURITY: the default branch returns the store's own text. That is safe by construction
// and not by inspection — store.go's errors name the ENTRY and never wrap the stored value
// (see decode's SECURITY note), which is the property that lets this be verbatim.
func sopsStoreError(reqID uint64, op, name string, err error) ipc.Response {
	switch {
	case errors.Is(err, backend.ErrNotFound):
		// Only rm can reach this: removing a name nobody stored. It is the CALLER's typo,
		// so CodeBadRequest (av exits 2), and it must stay distinguishable from success —
		// reporting "removed" over a mistyped name would leave a user believing a key is
		// gone that is still there, or that the right one went when it did not.
		return errResp(reqID, ipc.CodeBadRequest, fmt.Sprintf("sops %s %q: no such SOPS identity", op, name))
	case errors.Is(err, ErrLocked):
		// The session's TTL can expire between the unlock gate and the write. Same
		// situation as the gate, so the same actionable text.
		return errResp(reqID, ipc.CodeLocked, sopsLockedMsg(op))
	default:
		return errResp(reqID, ipc.CodeInternal, err.Error())
	}
}

// sopsManageAudit records ONE entry per completed mutation: which identity, at which tier.
// keygen, put and rm all write here; a listing does not, exactly as `resolve` audits an
// issue and `status` audits nothing.
//
// SECURITY (structural): audit.Event has no value field, so nothing here CAN carry key
// material. The arguments still matter, and they are why this takes strings rather than the
// request: name is the identity name the caller sent, tier is the one sopsValidate returned,
// and no parameter of this function is derived from a key. sopsPut in particular holds the
// private key in scope at the call site and has nowhere to put it.
//
// Detail is the literal "ok" on every call, drawn from the same CLOSED set sops_unwrap uses
// (sopsAuditDetails in sops_rpc_test.go restates it). Mutations are audited only when they
// SUCCEEDED — a refused request wrote nothing, and the outcomes it could report are the
// error responses above.
func (s *Server) sopsManageAudit(kind, name string, tier sopsplugin.Tier) {
	s.audit.Log(audit.Event{Kind: kind, Name: name, Tier: string(tier), Detail: "ok"})
}
