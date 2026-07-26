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
//
// Every case also asserts the error does not quote its input back. keys.txt is where
// private keys live, so anything DecodeIdentity says about a line it rejected can end
// up in a log or a CI transcript. The assertion is on the whole table, not just the
// secret-key case, because the leak would arrive as an innocuous-looking %w on some
// future error path — the sort of change nothing else here would catch.
func TestDecodeIdentityRejectsGarbage(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, input string }{
		{"empty", ""},
		{"not bech32", "hello world"},
		{"truncated", "AGE-PLUGIN-AV-1"},
		// Uppercase Q: a lowercase one would trip bech32's mixed-case guard before the
		// checksum is ever verified, testing a different rejection than the name claims.
		{"bad checksum", sopsplugin.EncodeIdentity(id.Recipient()) + "Q"},
		// A plain recipient in the identity slot is the mistake a first-time user makes.
		{"recipient not identity", id.Recipient().String()},
		// The dangerous paste: the private key itself, in the slot that wants a pointer
		// to it. This is the input the no-echo assertion below exists for.
		{"secret key not identity", id.String()},
		// Correct plugin, payload that is not a recipient: reaches the second parse step.
		{"right plugin wrong payload", plugin.EncodeIdentity(sopsplugin.PluginName, []byte("not a recipient"))},
		// A recipient of the right shape but the wrong curve point size.
		{"short payload", plugin.EncodeIdentity(sopsplugin.PluginName, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sopsplugin.DecodeIdentity(tc.input)
			if err == nil {
				t.Fatalf("want an error, got recipient %v", got)
			}
			if got != nil {
				t.Errorf("want a nil recipient alongside the error, got %v", got)
			}
			if tc.input != "" && strings.Contains(err.Error(), tc.input) {
				t.Errorf("error quotes the rejected input back; it must not: %v", err)
			}
		})
	}
}

// TestDecodeIdentityNamesTheCommonMistakes pins the diagnostics, not just the rejection.
// age collapses every one of these into "not a plugin identity: <nil>" — it formats an
// already-nil error — so without these branches the user gets a message that names
// neither what they pasted nor what belongs there instead.
func TestDecodeIdentityNamesTheCommonMistakes(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, input, want string }{
		{"plain recipient", id.Recipient().String(), "recipient"},
		{"plugin recipient", plugin.EncodeRecipient(sopsplugin.PluginName, []byte("x")), "recipient"},
		{"private key", id.String(), "private key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sopsplugin.DecodeIdentity(tc.input)
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should say %q, got: %v", tc.want, err)
			}
			// Naming the mistake is half of it; the user also has to be told what to
			// run to get the right string.
			if !strings.Contains(err.Error(), "av sops identity") {
				t.Errorf("error should point at the command that prints an identity, got: %v", err)
			}
		})
	}
}

// TestPluginNameIsTheSingleSource fails if PluginName drifts from the name age actually
// encodes. The binary name, the identity prefix, and the daemon lookup will all key off
// this one string; nothing else checks that they still agree.
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
