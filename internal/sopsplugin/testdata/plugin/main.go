// Command age-plugin-avtest is a TEST-ONLY age plugin used by the spike in
// internal/sopsplugin. It proves that the age plugin protocol delivers ordinary
// X25519 stanzas to a plugin. It takes its identity from AV_TEST_PLUGIN_KEY and
// is never built into a release — see the testdata/ placement.
package main

import (
	"fmt"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

type identity struct{ inner *age.X25519Identity }

// Unwrap receives EVERY stanza in the file header, including plain X25519 ones,
// and delegates to the standard age identity.
func (i *identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	return i.inner.Unwrap(stanzas)
}

func main() {
	p, err := plugin.New("avtest")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	p.HandleIdentity(func(_ []byte) (age.Identity, error) {
		inner, err := age.ParseX25519Identity(os.Getenv("AV_TEST_PLUGIN_KEY"))
		if err != nil {
			return nil, err
		}
		return &identity{inner: inner}, nil
	})
	os.Exit(p.Main())
}
