// Package client is the av-side RPC client with daemon autostart.
package client

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// defaultHealWait bounds the post-Shutdown poll for the upgraded daemon to come up. It
// is a field (healWait) so tests can shrink it; see withHealWait.
const defaultHealWait = 5 * time.Second

// Client is a thin RPC client bound to a daemon socket path.
//
// noPrompt is the agent opt-out from on-demand biometric unlock: when set (cmd/av maps
// AV_NO_PROMPT to it) the Resolve/Add/Remove RPCs carry NoPrompt so a locked daemon
// session returns CodeLocked (exit 69) instead of blocking the agent on a Touch ID.
//
// version is av's own build version (cmd/av's ldflags-injected tag, threaded via
// WithVersion). ensureFresh compares it to the daemon's version to self-heal a stale
// daemon after a brew upgrade (see ensureFresh); healed guards that heal to AT MOST once.
type Client struct {
	path     string
	noPrompt bool
	version  string
	healed   bool          // heal is attempted at most once per client (win or lose)
	healWait time.Duration // bound on the post-Shutdown poll (0 means defaultHealWait)
}

// ErrDaemonOutdated reports a version skew the client refused to auto-heal: an agent run
// (NoPrompt) must never restart the user's daemon, so ensureFresh returns this for cmd/av
// to print and exit non-zero — a human then restarts the daemon. Av/Avd are the versions.
type ErrDaemonOutdated struct{ Av, Avd string }

func (e *ErrDaemonOutdated) Error() string {
	return fmt.Sprintf("avd outdated (%s) vs av (%s) — ask a human: brew services restart agentvault", e.Avd, e.Av)
}

// New returns a Client for the daemon socket at path.
func New(path string) *Client { return &Client{path: path} }

// WithNoPrompt sets the agent opt-out (AV_NO_PROMPT) on the client so Resolve/Add/Remove
// carry NoPrompt — a locked session then returns CodeLocked rather than firing Touch ID.
// It returns the client for one-line construction (client.New(p).WithNoPrompt(b)).
func (c *Client) WithNoPrompt(noPrompt bool) *Client {
	c.noPrompt = noPrompt
	return c
}

// WithVersion records av's own build version so ensureFresh can detect a stale daemon and
// self-heal it. It returns the client for one-line construction (chainable with
// WithNoPrompt). An empty/"dev" version never heals (see ensureFresh).
func (c *Client) WithVersion(v string) *Client {
	c.version = v
	return c
}

// withHealWait shrinks the post-Shutdown poll bound so tests need not wait the full
// defaultHealWait. It is unexported (test-only) and chainable like the With* setters.
func (c *Client) withHealWait(d time.Duration) *Client {
	c.healWait = d
	return c
}

// ensureFresh self-heals a daemon left stale by a brew upgrade: when av's version differs
// from the running avd's (neither being the "dev"/unstamped sentinel), it either surfaces
// ErrDaemonOutdated (agents — NoPrompt) or restarts the old daemon (humans) so the freshly
// installed binary takes over. It heals AT MOST once per client (the healed guard wins-or-
// loses) and NEVER hangs: the human path polls only up to healWait, then warns and proceeds.
//
// It returns nil (no-op) when there is nothing safe to heal: an unstamped/dev av (we must
// never restart a release daemon from a dev build), an unreachable daemon (the normal
// dial/autostart brings up the right binary), or a matched/dev daemon (no skew). Work
// methods call it first; Version/Shutdown/Ping do NOT (avoiding recursion).
func (c *Client) ensureFresh() error {
	if c.healed || c.version == "" || c.version == "dev" {
		return nil // never heal from a dev/unstamped av, and never more than once
	}
	v, err := c.Version()
	if err != nil {
		return nil // daemon unreachable — the dial/autostart path will bring up the right one
	}
	c.healed = true // heal is attempted at most once, win or lose — prevents loops
	if v.Version == "dev" || v.Version == c.version {
		return nil // no skew, or a dev daemon (mixed dev/brew setup must not loop)
	}

	// SKEW: av and avd are different stamped releases (the brew-upgrade case).
	if c.noPrompt {
		// Agents never auto-restart the user's daemon — surface a clear error to pause.
		return &ErrDaemonOutdated{Av: c.version, Avd: v.Version}
	}

	fmt.Fprintf(os.Stderr, "agentvault: daemon upgraded (%s -> %s) — restarting\n", v.Version, c.version)
	_ = c.Shutdown() // the connection dropping as the old daemon exits IS success — ignore the error

	// Poll (bounded by healWait) for the upgraded binary: the next Version() that returns
	// our version means the new daemon is up (re-dial uses the existing autostart/retry).
	wait := c.healWait
	if wait <= 0 {
		wait = defaultHealWait
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(150 * time.Millisecond)
		if nv, nerr := c.Version(); nerr == nil && nv.Version == c.version {
			return nil // the new binary is up and matched — caller proceeds
		}
	}
	// Still skewed/unreachable after the bound: NEVER hang — warn loudly and proceed anyway.
	fmt.Fprintf(os.Stderr, "WARNING: daemon still %s after restart attempt; run: brew services restart agentvault\n", v.Version)
	return nil
}

// dial opens one connection to the daemon, autostarting avd (detached) and
// retrying if no daemon is listening yet. Callers own the returned conn and must
// Close it. It is the single dial path shared by one-shot call and the streaming
// scrub (which needs a persistent connection across multiple requests so the
// daemon's per-connection scrub state survives the whole stream).
func (c *Client) dial() (net.Conn, error) {
	conn, err := transport.Dial(c.path)
	if err != nil {
		if serr := autostart(c.path); serr != nil {
			return nil, fmt.Errorf("dial and autostart failed: %w", serr)
		}
		conn, err = dialRetry(c.path, 2*time.Second)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

// call dials the daemon, sends one request, and returns the response (one-shot:
// the connection is closed afterward). For multi-request streams that need a
// persistent connection, use dial directly (see scrub.go).
func (c *Client) call(req ipc.Request) (ipc.Response, error) {
	conn, err := c.dial()
	if err != nil {
		return ipc.Response{}, err
	}
	defer conn.Close()
	if err := ipc.NewEncoder(conn).Encode(req); err != nil {
		return ipc.Response{}, err
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(conn).Decode(&resp); err != nil {
		return ipc.Response{}, err
	}
	return resp, nil
}

// dialRetry polls transport.Dial every ~100ms until it succeeds or total elapses,
// returning the last dial error on timeout. Used after autostart while the freshly
// spawned daemon binds its socket.
func dialRetry(path string, total time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(total)
	var err error
	for {
		var conn net.Conn
		conn, err = transport.Dial(path)
		if err == nil {
			return conn, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("daemon did not come up within %s: %w", total, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Resolve issues the "resolve" RPC: it sends the profile and the raw
// agentvault.yaml bytes (av stays thin — avd parses and resolves) and returns
// the logical name -> value map. On a daemon error it returns resp.Error (a
// *ipc.RPCError) so the caller can inspect its Code (e.g. CodeLocked/CodeDenied).
func (c *Client) Resolve(profile string, manifestBytes []byte) (map[string]string, error) {
	if err := c.ensureFresh(); err != nil {
		return nil, err // *ErrDaemonOutdated (agents) — cmd/av prints "ask a human" and exits
	}
	p, _ := json.Marshal(ipc.ResolveParams{Profile: profile, Manifest: manifestBytes, NoPrompt: c.noPrompt})
	resp, err := c.call(ipc.Request{ID: 1, Method: "resolve", Params: p})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error // caller inspects Code (Locked/Denied)
	}
	var r ipc.ResolveResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return r.Values, nil
}

// Unlock issues the "unlock" RPC: in production this is the call that fires Touch
// ID. On a daemon error it returns resp.Error (a *ipc.RPCError) so the caller can
// map its Code (CodeLocked/CodeDenied) to an exit code. The StatusResult reply is
// not needed by the caller (av status reports remaining), so only the error matters.
func (c *Client) Unlock() error {
	if err := c.ensureFresh(); err != nil {
		return err
	}
	resp, err := c.call(ipc.Request{ID: 1, Method: "unlock"})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error // caller inspects Code (Locked/Denied)
	}
	return nil
}

// Lock issues the "lock" RPC, re-locking the session and clearing issued values.
func (c *Client) Lock() error {
	if err := c.ensureFresh(); err != nil {
		return err
	}
	resp, err := c.call(ipc.Request{ID: 1, Method: "lock"})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	return nil
}

// Shutdown issues the "shutdown" RPC, asking the daemon to exit gracefully so a newly
// upgraded binary can take over (the self-healing restart). The daemon responds "ok"
// BEFORE it exits (respond-then-exit), but the connection may still drop as the process
// dies — so a POST-send read error is treated as SUCCESS: the daemon going away is
// exactly the goal. Only a dial/send failure (we never reached the daemon) is an error.
func (c *Client) Shutdown() error {
	conn, err := c.dial()
	if err != nil {
		return err // never reached the daemon
	}
	defer conn.Close()
	if err := ipc.NewEncoder(conn).Encode(ipc.Request{ID: 1, Method: "shutdown"}); err != nil {
		return err // never delivered the request
	}
	// The request is delivered. A decode error now means the daemon exited before/while
	// replying — which is the desired outcome — so treat any post-send error as success.
	var resp ipc.Response
	if err := ipc.NewDecoder(conn).Decode(&resp); err != nil {
		return nil // connection dropped as the daemon exited == shutdown succeeded
	}
	if resp.Error != nil {
		return resp.Error
	}
	return nil
}

// Status issues the "status" RPC and returns the session lock state and remaining
// unlock seconds. The reply NEVER carries a value (StatusResult has no value field).
func (c *Client) Status() (locked bool, remaining int, err error) {
	if err := c.ensureFresh(); err != nil {
		return false, 0, err
	}
	resp, err := c.call(ipc.Request{ID: 1, Method: "status"})
	if err != nil {
		return false, 0, err
	}
	if resp.Error != nil {
		return false, 0, resp.Error
	}
	var r ipc.StatusResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return false, 0, err
	}
	return r.Locked, r.RemainingSeconds, nil
}

// Add issues the "add" RPC: it writes value under locator in the given backend's vault.
// SECURITY: value travels ONLY in the AddParams over the 0600 peer-cred socket; cmd/av
// reads it from a TTY (echo off) or stdin, NEVER from argv, so it can't leak via shell
// history / ps. On a daemon error it returns resp.Error (a *ipc.RPCError) so the caller
// can map its Code (e.g. CodeBadRequest for a read-only backend) to an exit code.
func (c *Client) Add(backend, locator string, value []byte) error {
	if err := c.ensureFresh(); err != nil {
		return err
	}
	p, _ := json.Marshal(ipc.AddParams{Backend: backend, Locator: locator, Value: value, NoPrompt: c.noPrompt})
	resp, err := c.call(ipc.Request{ID: 1, Method: "add", Params: p})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	return nil
}

// Remove issues the "rm" RPC: it deletes locator from the given backend's vault. It
// carries no value (removal is by name only). A missing name surfaces as resp.Error
// with CodeBadRequest so the caller can report it clearly.
func (c *Client) Remove(backend, locator string) error {
	if err := c.ensureFresh(); err != nil {
		return err
	}
	p, _ := json.Marshal(ipc.RmParams{Backend: backend, Locator: locator, NoPrompt: c.noPrompt})
	resp, err := c.call(ipc.Request{ID: 1, Method: "rm", Params: p})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	return nil
}

// SopsUnwrap issues the "sops_unwrap" RPC on behalf of age-plugin-av: it ferries one
// file's header stanzas to the daemon and returns the per-FILE key the daemon unwrapped
// with a stored SOPS identity. The SOPS private key never leaves avd, and the reply
// decrypts exactly one file. There is no `av` subcommand for this — the caller is the
// plugin, not av.
//
// recipient crosses as []byte rather than an *age.X25519Recipient, and the asymmetry with
// the daemon (which parses it, so Store.FindByRecipient takes the typed value and the
// comparison cannot go wrong there) is deliberate: this package is linked into the thin
// av, which must import no age at all — see TestAvStaysThin in cmd/av. Parsing here would
// drag that tree into every av invocation.
//
// It carries the bech32 "age1…" TEXT: pass []byte(recipient.String()) and nothing else.
// encoding/json already base64s a []byte, so re-encoding it here would arrive as
// base64-of-base64, fail the daemon's parse, and report every file as one this vault holds
// no key for — the same answer a file that genuinely is not yours gets.
//
// SECURITY: the returned file key IS a secret. It is handed to the caller and must reach
// no log and no error. On a daemon error it returns resp.Error (a *ipc.RPCError) so the
// caller can map its Code — and relay its Message, which for CodeLocked is the only thing
// separating a locked vault from a dangerous-tier identity refused under no_prompt.
func (c *Client) SopsUnwrap(recipient []byte, stanzas []ipc.SopsStanza) ([]byte, error) {
	if err := c.ensureFresh(); err != nil {
		return nil, err
	}
	p, _ := json.Marshal(ipc.SopsUnwrapParams{Recipient: recipient, Stanzas: stanzas, NoPrompt: c.noPrompt})
	resp, err := c.call(ipc.Request{ID: 1, Method: "sops_unwrap", Params: p})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r ipc.SopsUnwrapResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return r.FileKey, nil
}

// SopsKeygen issues the "sops_keygen" RPC: the daemon generates a SOPS identity, stores it
// under name at tier ("" means the default, normal), and returns its PUBLIC half — the
// age1… recipient plus the AGE-PLUGIN-AV-1… pointer for keys.txt.
//
// SECURITY: the private key is generated inside avd and never crosses this socket in either
// direction. ipc.SopsIdentityInfo has no field that could carry one, so this method cannot
// return a key however it is called.
//
// The pointer comes back ready-made because `av` cannot build one: the encoder lives in
// internal/sopsplugin, which imports filippo.io/age, and this package is linked into the
// thin av (TestAvStaysThin). av prints and writes that string; it never parses it.
func (c *Client) SopsKeygen(name, tier string) (ipc.SopsIdentityInfo, error) {
	if err := c.ensureFresh(); err != nil {
		return ipc.SopsIdentityInfo{}, err
	}
	p, _ := json.Marshal(ipc.SopsKeygenParams{Name: name, Tier: tier, NoPrompt: c.noPrompt})
	return c.sopsIdentityCall("sops_keygen", p)
}

// SopsPut issues the "sops_put" RPC: it stores an EXISTING age private key under name at
// tier and returns the same public view SopsKeygen does. `av sops import` calls it once per
// key it read out of the user's keys.txt.
//
// SECURITY: key carries the AGE-SECRET-KEY-1… private key and is the ONLY value this
// package ever sends on the SOPS surface. It travels solely over the 0600 peer-cred-gated
// unix socket, exactly like Add's value, and must reach no log and no error — including the
// caller's: a failed import must not print what it was importing. av reads these bytes from
// a file and ferries them without interpreting them, which is what keeps av free of age.
func (c *Client) SopsPut(name, tier string, key []byte) (ipc.SopsIdentityInfo, error) {
	if err := c.ensureFresh(); err != nil {
		return ipc.SopsIdentityInfo{}, err
	}
	p, _ := json.Marshal(ipc.SopsPutParams{Name: name, Tier: tier, Value: key, NoPrompt: c.noPrompt})
	return c.sopsIdentityCall("sops_put", p)
}

// SopsList issues the "sops_list" RPC: every stored SOPS identity, sorted by name, with its
// tier, recipient and pointer. It is what `av sops ls` prints, and what `av sops recipient`
// and `av sops identity` read a single field out of — those need no RPC of their own, since
// this reply already carries both strings for every identity.
//
// SECURITY: the reply is built from ipc.SopsIdentityInfo, which has no key field, so
// `av sops ls` output — a thing that lands in terminals, CI logs and screenshots — cannot
// contain a private key.
func (c *Client) SopsList() ([]ipc.SopsIdentityInfo, error) {
	if err := c.ensureFresh(); err != nil {
		return nil, err
	}
	p, _ := json.Marshal(ipc.SopsListParams{NoPrompt: c.noPrompt})
	resp, err := c.call(ipc.Request{ID: 1, Method: "sops_list", Params: p})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var r ipc.SopsListResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return nil, err
	}
	return r.Identities, nil
}

// SopsRemove issues the "sops_rm" RPC: it deletes the identity stored under name. It
// carries no value, so it can never leak key material. A name nobody stored comes back as
// resp.Error with CodeBadRequest rather than a silent success — deleting the only copy of a
// key is not something to report over a typo.
//
// The daemon removes what it is told to. The "are you sure — files encrypted to this key
// become unreadable" confirmation belongs to `av sops rm`, which is where the TTY is.
func (c *Client) SopsRemove(name string) error {
	if err := c.ensureFresh(); err != nil {
		return err
	}
	p, _ := json.Marshal(ipc.SopsRmParams{Name: name, NoPrompt: c.noPrompt})
	resp, err := c.call(ipc.Request{ID: 1, Method: "sops_rm", Params: p})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	return nil
}

// sopsIdentityCall sends one already-marshaled request whose reply is a single
// SopsIdentityInfo — the shape keygen and put share. It exists so the two cannot drift
// apart in how they decode a reply or surface a daemon rejection (*ipc.RPCError, whose Code
// cmd/av maps to an exit code).
func (c *Client) sopsIdentityCall(method string, params []byte) (ipc.SopsIdentityInfo, error) {
	resp, err := c.call(ipc.Request{ID: 1, Method: method, Params: params})
	if err != nil {
		return ipc.SopsIdentityInfo{}, err
	}
	if resp.Error != nil {
		return ipc.SopsIdentityInfo{}, resp.Error
	}
	var r ipc.SopsIdentityInfo
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return ipc.SopsIdentityInfo{}, err
	}
	return r, nil
}

// Setup issues the "setup" RPC: it asks the daemon to provision the local age store
// (identity + empty vault) and returns the on-disk paths plus whether files were created
// this call. SECURITY: SetupParams/SetupResult carry NO secret — only two booleans and
// paths — so nothing sensitive crosses the wire here. On a daemon error it returns
// resp.Error (a *ipc.RPCError) so the caller can map its Code to an exit code.
func (c *Client) Setup(p ipc.SetupParams) (ipc.SetupResult, error) {
	// Self-heal a stale daemon BEFORE provisioning: setup writes the identity via the
	// daemon, so it must run against the upgraded binary (e.g. a keystore fix only lands
	// in the new avd). ErrDaemonOutdated (agents) propagates so they pause.
	if err := c.ensureFresh(); err != nil {
		return ipc.SetupResult{}, err
	}
	pb, _ := json.Marshal(p)
	resp, err := c.call(ipc.Request{ID: 1, Method: "setup", Params: pb})
	if err != nil {
		return ipc.SetupResult{}, err
	}
	if resp.Error != nil {
		return ipc.SetupResult{}, resp.Error
	}
	var r ipc.SetupResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return ipc.SetupResult{}, err
	}
	return r, nil
}

// Service issues the "service" RPC (action: "enable" | "disable" | "status") to
// manage avd's login-item registration, returning the active backend + resulting
// State. SECURITY: ServiceParams/ServiceResult carry no secret. enable/disable are
// the only mutating actions; status is read-only.
func (c *Client) Service(action string) (ipc.ServiceResult, error) {
	pb, _ := json.Marshal(ipc.ServiceParams{Action: action})
	resp, err := c.call(ipc.Request{ID: 1, Method: "service", Params: pb})
	if err != nil {
		return ipc.ServiceResult{}, err
	}
	if resp.Error != nil {
		return ipc.ServiceResult{}, resp.Error
	}
	var r ipc.ServiceResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return ipc.ServiceResult{}, err
	}
	return r, nil
}

// Version issues the "version" RPC and returns avd's build version plus the active
// identity-protection tier and Enclave availability. SECURITY: VersionResult is pure
// metadata (no value field), so this reply can never carry a secret. On a daemon error
// it returns resp.Error; callers (av version) treat an unreachable daemon as "not running"
// rather than a hard failure.
func (c *Client) Version() (ipc.VersionResult, error) {
	resp, err := c.call(ipc.Request{ID: 1, Method: "version"})
	if err != nil {
		return ipc.VersionResult{}, err
	}
	if resp.Error != nil {
		return ipc.VersionResult{}, resp.Error
	}
	var r ipc.VersionResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return ipc.VersionResult{}, err
	}
	return r, nil
}

// Ping issues the "ping" RPC and returns the daemon's reply (expected "pong").
func (c *Client) Ping() (string, error) {
	resp, err := c.call(ipc.Request{ID: 1, Method: "ping"})
	if err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", resp.Error
	}
	var pong string
	if err := json.Unmarshal(resp.Result, &pong); err != nil {
		return "", err
	}
	return pong, nil
}
