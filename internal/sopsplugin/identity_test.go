package sopsplugin_test

import (
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/beshkenadze/agentvault/internal/sopsplugin"
)

// TestEncodeDecodeIdentityRoundTrip pins the contract keys.txt depends on: what
// EncodeIdentity writes, DecodeIdentity reads back as the same recipient. If the payload
// format ever changes, every keys.txt in the wild stops resolving, so this is the test
// that has to break first.
func TestEncodeDecodeIdentityRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r := id.Recipient()

	s := sopsplugin.EncodeIdentity(r)
	// age derives this prefix from PluginName by uppercasing it. Asserting the literal
	// string rather than recomputing it is deliberate: the prefix is user-visible in
	// keys.txt and in every doc example, so a change to PluginName must fail here.
	if !strings.HasPrefix(s, "AGE-PLUGIN-AV-1") {
		t.Fatalf("got %q, want an AGE-PLUGIN-AV-1 prefix", s)
	}

	got, err := sopsplugin.DecodeIdentity(s)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != r.String() {
		t.Fatalf("round trip changed the recipient: %s != %s", got, r)
	}
}

// TestDecodeIdentityRejectsOtherPlugins guards the case where keys.txt names a plugin
// that is not us. Accepting it would send another plugin's identity data to avd, which
// would fail deeper in the stack with a far less obvious message.
func TestDecodeIdentityRejectsOtherPlugins(t *testing.T) {
	foreign := plugin.EncodeIdentity("yubikey", []byte("x"))
	if foreign == "" {
		t.Fatal("plugin.EncodeIdentity rejected the name; the fixture is wrong, not the code under test")
	}
	_, err := sopsplugin.DecodeIdentity(foreign)
	if err == nil {
		t.Fatal("want an error for a foreign plugin identity, got nil")
	}
	// The message has to name the offending plugin or a user staring at a keys.txt with
	// several identities in it cannot tell which line is wrong.
	if !strings.Contains(err.Error(), "yubikey") {
		t.Errorf("error should name the foreign plugin, got: %v", err)
	}
}

// TestDecodeIdentityRejectsGarbage covers the shapes a hand-edited or half-pasted
// keys.txt actually produces. Every one must return an error rather than panic: this
// parses attacker-influenceable text (a repo's checked-in dotfiles) in a process that
// later talks to the daemon.
func TestDecodeIdentityRejectsGarbage(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, input string }{
		{"empty", ""},
		{"not bech32", "hello world"},
		{"truncated", "AGE-PLUGIN-AV-1"},
		{"bad checksum", sopsplugin.EncodeIdentity(id.Recipient()) + "q"},
		// A plain recipient in the identity slot is the mistake a first-time user makes.
		{"recipient not identity", id.Recipient().String()},
		// Correct plugin, payload that is not a recipient: reaches the second parse step.
		{"right plugin wrong payload", plugin.EncodeIdentity("av", []byte("not a recipient"))},
		// A recipient of the right shape but the wrong curve point size.
		{"short payload", plugin.EncodeIdentity("av", nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sopsplugin.DecodeIdentity(tc.input)
			if err == nil {
				t.Fatalf("want an error, got recipient %v", got)
			}
			if got != nil {
				t.Errorf("want a nil recipient alongside the error, got %v", got)
			}
		})
	}
}

// TestPluginNameIsTheSingleSource fails if PluginName drifts from the name age actually
// encodes. The binary name, the identity prefix, and the daemon lookup all key off this
// one string; nothing else checks that they still agree.
func TestPluginNameIsTheSingleSource(t *testing.T) {
	if sopsplugin.PluginName != "av" {
		t.Fatalf("PluginName = %q; the binary must stay age-plugin-av for age to discover it", sopsplugin.PluginName)
	}
	name, _, err := plugin.ParseIdentity(plugin.EncodeIdentity(sopsplugin.PluginName, []byte("payload")))
	if err != nil {
		t.Fatalf("age rejects PluginName %q: %v", sopsplugin.PluginName, err)
	}
	if name != sopsplugin.PluginName {
		t.Fatalf("age round-trips PluginName as %q, not %q", name, sopsplugin.PluginName)
	}
}
