// Command age-plugin-av is AgentVault's age plugin: it lets sops, helm secrets, and
// kustomize+ksops decrypt with a SOPS key that never leaves the daemon.
//
// age discovers plugins by FILENAME, so this binary must be installed as age-plugin-av.
// The name is derived from sopsplugin.PluginName rather than spelled again here, because a
// rename reaching only one of the two leaves age hunting for a plugin that is not there.
// age says so precisely — `"av" plugin not found: exec: "age-plugin-av": executable file
// not found in $PATH` — but through sops that line is wrapped inside the error box beneath
// a generic "no master key" summary, easy to scroll past on the way to blaming the keys.
//
// It holds no key and performs no cryptography. It forwards the file's header stanzas to
// avd, which unwraps them inside its mlock'd, presence-gated session and returns only the
// per-FILE key. So nothing decryptable sits on disk, and a compromised sops learns one
// file's key rather than the identity behind every file.
package main

import (
	"errors"
	"fmt"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/beshkenadze/agentvault/internal/client"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/sopsplugin"
	"github.com/beshkenadze/agentvault/internal/transport"
)

func main() {
	p, err := plugin.New(sopsplugin.PluginName)
	if err != nil {
		// The ONLY write to stderr in this binary, and only because it happens before
		// p.Main: there is no protocol yet to report through. Everything after this point
		// returns its error to the framework instead — the protocol owns the process's
		// streams, and a stray print into them corrupts the stanza framing.
		fmt.Fprintln(os.Stderr, "age-plugin-av:", err)
		os.Exit(1)
	}
	p.HandleIdentity(newIdentity)
	os.Exit(p.Main())
}

// newIdentity turns one AGE-PLUGIN-AV-1... payload into the identity age calls Unwrap on.
//
// data reaches the daemon UNTOUCHED. EncodeIdentity put the recipient's bech32 "age1..."
// TEXT there (internal/sopsplugin/identity.go) and the daemon parses exactly that, so any
// re-encoding on the way — base64, hex, or a "normalising" round trip through age — arrives
// as something its parse refuses. The damage is quiet rather than loud: every file then
// reports as one this vault holds no key for, which is the same answer a file that
// genuinely is not yours gets.
//
// It deliberately does NOT parse data as a recipient first. The daemon already does, before
// touching the vault and before spending any presence check, and it answers with a message
// written for that exact fault. A parser here would be a second source of truth for "what
// is a recipient", free to drift from the one Store.FindByRecipient matches against, and
// its error would be one more locally-invented string — the substitution this file goes out
// of its way to avoid for CodeLocked. All it would buy is one socket round trip on a path
// only a corrupt keys.txt reaches.
func newIdentity(data []byte) (age.Identity, error) {
	path, err := transport.DefaultSocketPath()
	if err != nil {
		return nil, fmt.Errorf("AgentVault: %v", err)
	}
	// AV_NO_PROMPT is read here rather than reused from cmd/av, whose noPrompt() is
	// unexported and whose binary must not link this one's dependencies. Threading it is
	// what makes a locked vault answer immediately instead of firing a biometric prompt at
	// a machine with nobody in front of it: a plugin that blocks stalls sops, and through
	// sops it stalls helm, with no way for an agent to recover.
	cl := client.New(path).WithNoPrompt(os.Getenv("AV_NO_PROMPT") != "")
	// No WithVersion, deliberately: that arms the client's self-heal, which SHUTS DOWN and
	// restarts the user's daemon on a version skew. Mid-`sops` is the wrong moment to do
	// that to a machine, and `av` already heals it on the next ordinary command.
	return &daemonIdentity{client: cl, recipient: data}, nil
}

// daemonIdentity is an age.Identity backed by avd. Its two fields are a socket path and a
// PUBLIC key, so this process holds nothing worth stealing even while it is running.
type daemonIdentity struct {
	client    *client.Client
	recipient []byte
}

// Unwrap ferries one file's header stanzas to the daemon and returns the per-FILE key it
// unwrapped with the stored identity. age hands over EVERY stanza in the header, including
// ordinary X25519 ones — proven by the Task 1 spike — which is what lets encrypted files
// keep their normal age1... recipients and leaves Flux, CI, and teammates untouched.
//
// SECURITY: the returned value is a secret. It goes straight back to age and reaches no
// error, no log, and no stream; the failure paths below never hold it.
func (i *daemonIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	ss := make([]ipc.SopsStanza, 0, len(stanzas))
	for _, s := range stanzas {
		ss = append(ss, ipc.SopsStanza{Type: s.Type, Args: s.Args, Body: s.Body})
	}
	fileKey, err := i.client.SopsUnwrap(i.recipient, ss)
	if err != nil {
		return nil, daemonError(err)
	}
	return fileKey, nil
}

// daemonError renders a daemon failure for a human reading sops's output. sops collects
// identity-loading errors and prints them only when decryption fails outright, so the text
// arrives with no context around it — hence the "AgentVault: " prefix, which says which of
// the several things in a `helm secrets` pipeline refused.
//
// The message is the DAEMON'S, never a local substitute, and CodeLocked is why. It covers
// two situations that need opposite responses: a genuinely locked vault, where `av unlock`
// is the fix, and a dangerous-tier identity whose fresh per-file check was skipped because
// this caller set no_prompt — where the vault is already OPEN and `av unlock` changes
// nothing. Hard-coding the first turns the second into a loop: a human runs `av unlock`,
// nothing changes, the agent retries, the identical error comes back. cmd/av's renderer
// maps CodeLocked to its own fixed string and never sees this path, so this is the last
// layer that can still tell the two apart.
//
// CodeNoMatch is the ONE code that is not relayed, and it is the reason a keys.txt with
// more than one AgentVault pointer works at all. age tries identities in sequence and
// advances to the next ONLY on age.ErrIncorrectIdentity; any other error aborts the whole
// decrypt. So a hard error for "this identity cannot decrypt this file" means the FIRST
// pointer decides the outcome for every file — with a personal key and a team key in
// keys.txt, files encrypted to the second are unreadable. Returning the sentinel makes age
// fall through, which is the entire behaviour of a plain multi-key keys.txt.
//
// This is a code test, never a message test. The daemon sends CodeNoMatch for the two
// refusals that genuinely mean "try another" and different codes for the rest; matching on
// prose instead would swallow the very refusals this function exists to surface, since
// several of them used to share CodeBadRequest.
//
// Everything else is formatted, not wrapped. Nothing downstream inspects the chain — the
// protocol carries err.Error() and nothing else — while %w would let an error that happens
// to wrap age.ErrIncorrectIdentity be read as "this file is not mine" by the framework's
// identity loop, turning a refusal a user needs to see into a silent "no identity matched".
func daemonError(err error) error {
	var rpc *ipc.RPCError
	if errors.As(err, &rpc) {
		if rpc.Code == ipc.CodeNoMatch {
			// Bare, not wrapped with the daemon's text: age's identity loop discards the
			// error it continues on, so any message attached here is thrown away rather
			// than shown. What that costs — a keys.txt whose pointers are ALL stale now
			// surfaces as age's generic "no identity matched" instead of naming the
			// recipient — is documented in internal/daemon/sops_rpc.go and Task 12.
			return age.ErrIncorrectIdentity
		}
		// SECURITY: RPCError.Message is the daemon's, which names identities, recipients
		// (public by construction), and refs — never a value. See internal/daemon/sops_rpc.go.
		return fmt.Errorf("AgentVault: %s", rpc.Message)
	}
	// Not a daemon reply at all: an unreachable socket, a failed autostart, or a version
	// skew the client refused to heal. That text is secret-free by construction too — paths
	// and versions.
	return fmt.Errorf("AgentVault: %v", err)
}
