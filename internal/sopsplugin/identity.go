// Package sopsplugin holds the AgentVault age plugin's daemon-facing logic.
package sopsplugin

import (
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// PluginName is the age plugin name, and the single source for every place that has to
// agree on it: age discovers the binary as "age-plugin-av", encodes identities as
// "AGE-PLUGIN-AV-1…", and reports that same name back when parsing one. Change it here
// or the three drift apart — a renamed binary just stops being found. age does name it
// ("av" plugin not found: exec: "age-plugin-av": …), but through sops that line is buried
// in the error box under a generic "no master key" summary and is easily missed.
const PluginName = "av"

// EncodeIdentity renders the pointer a user puts in keys.txt. It carries the RECIPIENT
// (a public key), never a private key: without a running avd and a presence check it
// decrypts nothing, so it is safe to commit, paste, or share. That property is what lets
// the whole design work — the thing on disk where the key used to be is now inert.
//
// The payload is the recipient's bech32 "age1…" text rather than its raw 32 bytes.
// age v1.3.1 exports no accessor for those bytes (X25519Recipient has only String and
// Wrap) and its bech32 helper is an internal package, so recovering them would mean
// reimplementing bech32 or taking a dependency. Neither is worth it to save ~50 bytes in
// a string nobody types and no protocol length-limits.
func EncodeIdentity(r *age.X25519Recipient) string {
	return plugin.EncodeIdentity(PluginName, []byte(r.String()))
}

// DecodeIdentity parses a pointer back into the recipient it names — the inverse of
// EncodeIdentity, and that is what it is FOR: it is how a test reads back what the daemon
// put in SopsIdentityInfo.Identity and checks it names the recipient it claims to
// (internal/daemon/sops_manage_test.go, store_test.go, identity_test.go).
//
// NO PRODUCTION PATH CALLS IT, and that is a property of age's plugin protocol rather than
// an omission here. age parses the AGE-PLUGIN-AV-1… line in keys.txt on the CLIENT side and
// execs age-plugin-av only once it has matched the plugin name, so this binary never sees a
// foreign identity, a stray age1… recipient or a pasted AGE-SECRET-KEY-… — those route to
// another plugin, or to age's own parsers, and never here. What it does see is the decoded
// payload, which is why cmd/age-plugin-av's newIdentity takes []byte and forwards it
// untouched. Even the framework's string-shaped entry point (plugin.HandleIdentityEncoding)
// hands over EncodeIdentity(p.name, data) — the pointer REBUILT from that payload under
// this plugin's own name, never the user's literal line. Routing that through the checks
// below would re-verify a string this package had just written.
//
// So the diagnostics below cannot reach a user today, and calling this from newIdentity
// would not change that — it would only add a second source of truth for "what is a
// recipient", free to drift from the one Store.FindByRecipient matches against. They are
// kept because they are the inverse's honest error paths and they are pinned by tests; if a
// caller ever does parse keys.txt lines itself, this is the function to reach for.
func DecodeIdentity(s string) (*age.X25519Recipient, error) {
	// Two kinds of key material land in the identity slot of a hand-edited keys.txt often
	// enough to name. Both die inside plugin.ParseIdentity as "not a plugin identity:
	// <nil>" — age formats an already-nil error there (plugin/encode.go:35) — which tells a
	// reader neither what was pasted nor what belongs instead. The prefix alone separates
	// them, and a prefix is a public format marker: these branches read no further
	// into s, so nothing key-shaped can reach the message.
	switch {
	case strings.HasPrefix(s, "age1"):
		// Covers a plain age1… recipient and an age1av1… plugin recipient alike;
		// neither is an identity, and the fix is the same for both.
		return nil, errors.New("that is an age recipient (a public key), not an identity: keys.txt needs the AGE-PLUGIN-AV-1... pointer that `av sops identity NAME` prints")
	case strings.HasPrefix(s, "AGE-SECRET-KEY-"):
		return nil, errors.New("that is an age private key: AgentVault holds the private key, so keys.txt needs the AGE-PLUGIN-AV-1... pointer that `av sops identity NAME` prints instead")
	}
	name, data, err := plugin.ParseIdentity(s)
	if err != nil {
		// Safe to wrap: none of ParseIdentity's three error paths reach the payload —
		// two interpolate an error, the third the plugin name it parsed out of the
		// human-readable prefix.
		return nil, fmt.Errorf("not an AgentVault age identity: %w", err)
	}
	if name != PluginName {
		return nil, fmt.Errorf("identity belongs to the %q age plugin, not %q", name, PluginName)
	}
	r, err := age.ParseX25519Recipient(string(data))
	if err != nil {
		// Deliberately not wrapped: age quotes the offending string back verbatim, and
		// reaching here means the payload of a well-formed AGE-PLUGIN-AV-1 identity is
		// not a recipient — corrupted or forged, since EncodeIdentity only ever writes
		// one. It is machine-generated either way, so age's detail tells the user
		// nothing they can act on, and dropping it keeps an arbitrary, possibly
		// attacker-chosen payload out of the logs. That it failed to parse is the
		// entire diagnostic; the line number is in keys.txt.
		return nil, errors.New("AgentVault identity does not encode a valid age recipient")
	}
	return r, nil
}
