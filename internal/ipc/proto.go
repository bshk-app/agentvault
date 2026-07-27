// Package ipc defines AgentVault's newline-delimited JSON-RPC framing.
package ipc

import (
	"bufio"
	"encoding/json"
	"io"
)

// Request is a single client call. Params is method-specific and may be empty.
type Request struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is the daemon's reply. Exactly one of Result/Error is set.
type Response struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

// RPCError carries a stable code so the agent can branch (e.g. locked vs denied).
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return e.Message }

// Stable error codes (extended in later phases).
const (
	CodeInternal     = 1
	CodeBadRequest   = 2
	CodeLocked       = 3 // vault locked — agent should ask a human to unlock
	CodeDenied       = 4 // dangerous-tier denied / no presence
	CodeUnauthorized = 5 // peer-credential check failed
	CodeRateLimited  = 6 // issuance rate limit tripped — mass enumeration forced a relock
	// CodeNoMatch says "this identity cannot decrypt this file; try another". It is the
	// ONLY code a caller iterating over identities may treat as fall-through, and it exists
	// because prose cannot carry that decision: the sops path has two refusals that mean
	// "try another" and three that mean "stop", and before this code all five arrived as
	// CodeBadRequest, distinguishable only by their wording. age-plugin-av maps it to
	// age.ErrIncorrectIdentity so age advances to the next identity in keys.txt; every
	// other code stays a hard error the user is shown. Sniffing message text instead would
	// swallow the very refusals the plugin exists to surface.
	CodeNoMatch = 7
)

// ResolveParams is the client request for `resolve`. The thin av sends the raw
// agentvault.yaml bytes; avd parses them (av links neither yaml nor backends).
//
// NoPrompt is the agent opt-out from on-demand biometric unlock: when false (a
// human at a TTY) a locked session is opened with one Touch ID before resolving;
// when true (set from AV_NO_PROMPT) a locked session returns CodeLocked instead, so
// the agent gets the clean exit-69 pause rather than blocking on a biometric prompt.
type ResolveParams struct {
	Profile  string `json:"profile"`
	Manifest []byte `json:"manifest"` // raw agentvault.yaml bytes
	NoPrompt bool   `json:"no_prompt,omitempty"`
}

// ResolveResult is the daemon reply: logical name -> secret value. This is the
// sole intended channel for plaintext values; they never appear in any RPCError.
type ResolveResult struct {
	Values map[string]string `json:"values"`
}

// AddParams is the client request for `add`: write a secret into a writable backend's
// vault. Backend is the backend id (e.g. "file") and Locator the name within it.
// SECURITY: Value carries the plaintext secret — this is the ONLY field that ever
// does, and it travels solely over the 0600 peer-cred-gated unix socket. It is never
// logged, never echoed, and never placed in an RPCError. `av` reads it from a TTY
// (echo off) or stdin, NEVER from argv, so it cannot leak via shell history / ps.
type AddParams struct {
	Backend string `json:"backend"`
	Locator string `json:"locator"`
	Value   []byte `json:"value"`
	// NoPrompt mirrors ResolveParams.NoPrompt: false auto-unlocks a locked session
	// with one Touch ID before the write; true (agents) returns CodeLocked instead.
	NoPrompt bool `json:"no_prompt,omitempty"`
}

// RmParams is the client request for `rm`: delete a secret from a writable backend's
// vault. It carries no value (removal is by name only), so it can never leak a secret.
type RmParams struct {
	Backend string `json:"backend"`
	Locator string `json:"locator"`
	// NoPrompt mirrors ResolveParams.NoPrompt: false auto-unlocks a locked session
	// with one Touch ID before the delete; true (agents) returns CodeLocked instead.
	NoPrompt bool `json:"no_prompt,omitempty"`
}

// SopsStanza is one age header stanza, ferried verbatim between age-plugin-av and the
// daemon. It mirrors age.Stanza field for field so the plugin can hand over exactly what
// age gave it, without interpreting a format neither side owns.
//
// SECURITY: Body is the WRAPPED file key — ciphertext, useless without the private key
// the daemon holds — so it is not a secret value in the sense AddParams.Value is. It is
// still never logged: it is the input half of an unwrap, and pairing it with anything
// else in a log line is a favour to whoever reads that log.
type SopsStanza struct {
	Type string   `json:"type"`
	Args []string `json:"args"`
	Body []byte   `json:"body"`
}

// SopsUnwrapParams asks the daemon to unwrap one file's key. Recipient names WHICH stored
// SOPS identity to use, so the daemon can reject a file this vault holds no key for
// BEFORE spending a presence prompt on it — the difference between `kustomize build` over
// a repo of other people's secrets costing zero prompts and costing one per file.
//
// SECURITY: Recipient is a PUBLIC key, not a secret. It carries the bech32 "age1…" TEXT
// of the recipient (see sopsplugin.EncodeIdentity), not 32 raw bytes — Go marshals []byte
// as base64, so what crosses the wire is base64-of-ASCII. Parse it with
// age.ParseX25519Recipient(string(p.Recipient)); a bytes.Equal against a raw key compares
// text to bytes and silently never matches.
//
// NoPrompt mirrors ResolveParams.NoPrompt: false lets a locked session be opened with one
// Touch ID before the unwrap; true (agents, via AV_NO_PROMPT) returns CodeLocked instead
// of blocking a machine on a biometric nobody is there to answer.
type SopsUnwrapParams struct {
	Recipient []byte       `json:"recipient"`
	Stanzas   []SopsStanza `json:"stanzas"`
	NoPrompt  bool         `json:"no_prompt,omitempty"`
}

// SopsUnwrapResult carries the per-FILE key. SECURITY: this IS a secret — but a
// single-file one. It decrypts exactly the file whose stanzas produced it and is useless
// for any other, which is the entire point of brokering here instead of handing over the
// identity: a compromised `sops` learns one file's key, not every file's.
type SopsUnwrapResult struct {
	FileKey []byte `json:"file_key"`
}

// SopsIdentityInfo describes ONE stored SOPS identity as everything outside the daemon is
// allowed to see it. It is the reply shape of sops_keygen and sops_put and the element of
// sops_list, so there is exactly one answer to "what may be said about an identity".
//
// SECURITY: it has no field that can hold a private key, and that is the point — the same
// reason sopsplugin.Info has none. Both public fields are derived from the key's PUBLIC
// half: Recipient is the bech32 "age1…" text, and Identity is the AGE-PLUGIN-AV-1… pointer
// built from it. Adding a key field here would defeat the sops/ namespace in one line.
//
// Identity is why these RPCs return more than a recipient. `av sops import` has to write
// that pointer into the user's keys.txt and `av` CANNOT compute it: the encoder lives in
// sopsplugin, which imports filippo.io/age, and TestAvStaysThin (cmd/av/deps_test.go)
// forbids av linking either. So the daemon — which already holds the key — renders the
// pointer, and av writes bytes it never has to understand. Without this field the thin-av
// rule and `av sops import` cannot both hold.
type SopsIdentityInfo struct {
	Name      string `json:"name"`
	Tier      string `json:"tier"`
	Recipient string `json:"recipient"` // public: the age1… key files are encrypted to
	Identity  string `json:"identity"`  // the AGE-PLUGIN-AV-1… pointer for keys.txt
}

// SopsKeygenParams asks the daemon to generate a NEW SOPS identity and store it under Name
// at Tier (empty means the documented default, normal).
//
// SECURITY: it carries no key material in EITHER direction. The private key is generated
// inside avd and goes straight into the vault; the reply is a SopsIdentityInfo, which
// structurally cannot carry it. That asymmetry with SopsPutParams is deliberate — keygen is
// the path on which a private key never exists outside this process at all.
//
// NoPrompt mirrors ResolveParams.NoPrompt: writing to the vault needs it open, so false
// opens a locked session with one Touch ID and true returns CodeLocked instead.
type SopsKeygenParams struct {
	Name     string `json:"name"`
	Tier     string `json:"tier,omitempty"`
	NoPrompt bool   `json:"no_prompt,omitempty"`
}

// SopsPutParams stores an EXISTING age private key under Name at Tier — the daemon half of
// `av sops import`, which sends one of these per key it found in the user's keys.txt.
//
// SECURITY: Value carries the AGE-SECRET-KEY-1… private key and is the ONLY field on the
// whole SOPS surface that ever holds key material. Treat it exactly as AddParams.Value:
// it travels solely over the 0600 peer-cred-gated unix socket, is never logged, never
// echoed, and never placed in an RPCError. `av` reads it from a file the user names and
// ferries it verbatim without parsing it — moving a string is not the same as linking age.
type SopsPutParams struct {
	Name     string `json:"name"`
	Tier     string `json:"tier,omitempty"`
	Value    []byte `json:"value"`
	NoPrompt bool   `json:"no_prompt,omitempty"`
}

// SopsListParams asks for every stored SOPS identity. It carries only the unlock opt-out:
// listing decrypts the vault, so it is a real read and gates like one.
type SopsListParams struct {
	NoPrompt bool `json:"no_prompt,omitempty"`
}

// SopsListResult is the reply for sops_list, sorted by name (Store.List sorts, so repeated
// `av sops ls` over an unchanged vault does not reshuffle). SECURITY: it is built from
// sopsplugin.Info, which has no key field, through a SopsIdentityInfo, which has none
// either — no private key can reach this reply by any route.
type SopsListResult struct {
	Identities []SopsIdentityInfo `json:"identities"`
}

// SopsRmParams deletes the identity stored under Name. It carries no value (removal is by
// name only), so it can never leak key material.
//
// The interactive "this destroys the only copy of a key" confirmation belongs to `av`, not
// here — the daemon removes what it is told to, exactly as the `rm` RPC does.
type SopsRmParams struct {
	Name     string `json:"name"`
	NoPrompt bool   `json:"no_prompt,omitempty"`
}

// ScrubParams is one chunk of a streamed scrub request. The client loops sending
// chunks via the "scrub" method, then flushes the overlap tail at EOF via
// "scrub_flush" (Data is empty/unused for flush). After a "scrub"/"scrub_flush"
// whose reply has More set, the client drains the daemon's leftover masked bytes via
// "scrub_drain" (Data unused) until More is false. Data carries raw bytes; only masked
// bytes flow back in ScrubResult, never a raw secret.
type ScrubParams struct {
	Data []byte `json:"data,omitempty"`
}

// ScrubResult is the masked output for a scrub/scrub_flush/scrub_drain request: only
// redacted bytes, never a raw secret.
//
// More signals that the daemon still has masked bytes buffered for this stream that
// did not fit in this response. Masking can inflate input far beyond a fixed factor —
// the placeholder is "{{AV:" + Name + "}}" and Name (the user's logical env-var name)
// is unbounded — so the daemon splits its OWN masked output by byte size to keep every
// response line under the Decoder's 1 MiB cap, regardless of how much the input
// inflated. While More is true the client MUST keep calling "scrub_drain" (which sends
// no further input) until More is false, so all masked bytes are delivered in order.
type ScrubResult struct {
	Masked []byte `json:"masked,omitempty"`
	More   bool   `json:"more,omitempty"`
}

// SetupParams is the client request for `setup`: provision the local age store.
// SECURITY: it carries NO secret — only booleans and a tier name. Rotate forces
// regeneration of the identity (and a fresh empty vault) even if a store already
// exists.
//
// Tier picks the protection tier explicitly ("enclave"/"keychain"/"plaintext"); ""
// means auto (Enclave where available → OS keychain/keyring, never plaintext).
// RequireEnclave forbids the Enclave→keychain downgrade so a Wrap failure becomes a hard
// error instead of a silent keychain fallback. Plaintext is the LEGACY flag kept for
// back-compat: when Tier is unset it is mapped to Tier=plaintext. New callers should set
// Tier directly.
type SetupParams struct {
	Rotate         bool   `json:"rotate,omitempty"`
	Plaintext      bool   `json:"plaintext,omitempty"`
	Tier           string `json:"tier,omitempty"`
	RequireEnclave bool   `json:"require_enclave,omitempty"`
}

// SetupResult is the daemon reply for `setup`. SECURITY: it reports ONLY on-disk
// PATHS and whether files were created this call — never the identity bytes or vault
// contents. Created is false when an existing store was left untouched (idempotent).
type SetupResult struct {
	VaultPath    string `json:"vault_path"`
	IdentityPath string `json:"identity_path"`
	Created      bool   `json:"created"`
}

// VersionResult is the daemon reply for `version`: avd's own build version, the ACTIVE
// identity-protection tier, and whether THIS BUILD can use the Secure Enclave (a
// capability — signed with the entitlement + cgo — independent of the active tier).
// SECURITY: it is pure metadata — a version string, a tier name, and a boolean — so it
// can NEVER carry a secret. Tier is "none" when no local vault is wired.
type VersionResult struct {
	Version          string `json:"version"`
	Tier             string `json:"tier"`
	EnclaveAvailable bool   `json:"enclave_available"`
}

// StatusResult is the daemon reply for unlock/status (and the ok reply for lock).
// SECURITY: it reports ONLY the session's lock state and the remaining unlock
// window — it has no field for an issued value and so can NEVER carry a secret.
type StatusResult struct {
	Locked           bool `json:"locked"`
	RemainingSeconds int  `json:"remaining_seconds"`
}

// ServiceParams is the client request for the "service" RPC: manage avd's login-item
// registration. Action is "enable" | "disable" | "status". SECURITY: it carries NO
// secret — only a verb — so nothing sensitive crosses the wire.
type ServiceParams struct {
	Action string `json:"action"`
}

// ServiceResult is the daemon reply for "service": the active backend
// ("smappservice" | "launchagent" | "") and the resulting registration State
// ("enabled" | "disabled" | "requires-approval"). Pure metadata — never a secret.
type ServiceResult struct {
	Backend string `json:"backend"`
	State   string `json:"state"`
}

// Encoder writes newline-delimited JSON values. json.Encoder already appends '\n'.
type Encoder struct{ enc *json.Encoder }

func NewEncoder(w io.Writer) *Encoder { return &Encoder{enc: json.NewEncoder(w)} }
func (e *Encoder) Encode(v any) error { return e.enc.Encode(v) }

// Decoder reads newline-delimited JSON values. A bufio.Scanner bounds line length.
type Decoder struct{ sc *bufio.Scanner }

func NewDecoder(r io.Reader) *Decoder {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1 MiB max line
	return &Decoder{sc: sc}
}

func (d *Decoder) Decode(v any) error {
	if !d.sc.Scan() {
		if err := d.sc.Err(); err != nil {
			return err
		}
		return io.EOF
	}
	return json.Unmarshal(d.sc.Bytes(), v)
}
