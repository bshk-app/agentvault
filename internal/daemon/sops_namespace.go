package daemon

import (
	"fmt"
	"strings"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/sopsplugin"
)

// A SOPS private key lives in the same vault as ordinary secrets, distinguished only by
// the sopsplugin.Namespace prefix. A prefix nothing enforces is a naming convention, and
// this file is what makes it a rule: the daemon refuses the namespace on the three RPCs
// that address a vault entry by name — resolve (server.go), add and rm (server.go).
//
// It is enforced HERE and not in cmd/av for two reasons. `av` is one client of a
// documented local socket, so a client-side check is advice anyone can route around by
// speaking the protocol directly. And `av` deliberately links no age code (cmd/av's
// TestAvStaysThin asserts it), which importing sopsplugin for the constant would end.
//
// BOTH halves matter. Reads: without the guard `av read sops/mykey` prints an
// AGE-SECRET-KEY-1… like any other secret. Writes: `av add sops/notes "reminder"` drops
// junk beside a real identity, and Store.FindByRecipient then has to reason about a
// corrupt neighbour on every lookup — which is exactly the failure Task 4's review hit.
// The only writer permitted in here is the av sops RPC surface, which owns the envelope
// format the Store reads back.

// sopsNamespaceBackend is the backend id whose vault holds the namespace: the local age
// file vault, the only store sopsplugin.Store reads and writes.
//
// The guard is scoped to it ON PURPOSE, because enforcement should be exactly as wide as
// the thing it protects. Every other backend has its own name space with its own
// meaning: av://1p/sops/prod/key addresses a 1Password VAULT called "sops", and
// av://keychain/sops/… a keychain service of that name. Neither can hold an AgentVault
// identity, so refusing them would deny a user for nothing.
//
// IF sopsplugin.Store is ever constructed over a different backend, this constant must
// follow it — otherwise the guard silently stops covering the namespace it exists for.
const sopsNamespaceBackend = "file"

// sopsNamespaceError reports a locator that addresses the reserved SOPS namespace,
// returning nil for everything else.
//
// The prefix test is against sopsplugin.Namespace ("sops/"), never the bare word: a
// HasPrefix(locator, "sops") would swallow "sopsucker" and every other name that merely
// begins with those four letters. Carrying the trailing slash in the constant is what
// makes the right answer the easy one, so this must not be written as a literal here.
//
// Two consequences worth stating, both of them just what Namespace matches:
//   - the bare name "sops" is NOT in the namespace (Store.each lists the "sops/" prefix,
//     which cannot match it, and Store.Put always writes "sops/"+name);
//   - the comparison is byte-exact, matching locators everywhere else in this repo
//     (agefile.Resolve is a map lookup, agefile.List a byte-prefix compare), so
//     "SOPS/mykey" is a different entry the Store can never reach.
//
// SECURITY: the message names the locator — a name the caller already typed — and
// nothing else. It never sees a value, and must never be given one.
func sopsNamespaceError(backendID, locator string) error {
	if backendID != sopsNamespaceBackend || !strings.HasPrefix(locator, sopsplugin.Namespace) {
		return nil
	}
	return fmt.Errorf("%q is in the reserved %s namespace — use av sops to manage SOPS identities",
		locator, sopsplugin.Namespace)
}

// sopsNamespaceRefError is sopsNamespaceError for an av:// reference, the form the
// resolver works in. A ref that does not parse returns nil: it cannot address the
// namespace, and the registry reports it with its own message rather than this one.
func sopsNamespaceRefError(ref string) error {
	p, err := backend.ParseRef(ref)
	if err != nil {
		return nil
	}
	return sopsNamespaceError(p.Backend, p.Locator)
}
