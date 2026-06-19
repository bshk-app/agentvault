package main

import (
	"strings"
	"testing"
)

// TestParseSetupArgsDefault: `av setup` with no flags leaves both booleans false.
func TestParseSetupArgsDefault(t *testing.T) {
	p, err := parseSetupArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Rotate || p.Plaintext {
		t.Fatalf("got rotate=%v plaintext=%v, want both false", p.Rotate, p.Plaintext)
	}
}

// TestParseSetupArgsFlags: --rotate and --plaintext set their respective booleans, in
// any order.
func TestParseSetupArgsFlags(t *testing.T) {
	p, err := parseSetupArgs([]string{"--rotate", "--plaintext"})
	if err != nil || !p.Rotate || !p.Plaintext {
		t.Fatalf("got rotate=%v plaintext=%v err=%v, want both true", p.Rotate, p.Plaintext, err)
	}
	p, err = parseSetupArgs([]string{"--plaintext"})
	if err != nil || p.Rotate || !p.Plaintext {
		t.Fatalf("got rotate=%v plaintext=%v err=%v, want plaintext only", p.Rotate, p.Plaintext, err)
	}
}

// TestParseSetupArgsTierFlags: --keychain/--enclave set Tier; --require-enclave sets
// Tier=enclave AND RequireEnclave (forbid downgrade).
func TestParseSetupArgsTierFlags(t *testing.T) {
	for _, tc := range []struct {
		flag        string
		wantTier    string
		wantRequire bool
	}{
		{"--keychain", "keychain", false},
		{"--enclave", "enclave", false},
		{"--require-enclave", "enclave", true},
	} {
		p, err := parseSetupArgs([]string{tc.flag})
		if err != nil || p.Tier != tc.wantTier || p.RequireEnclave != tc.wantRequire {
			t.Fatalf("%s: tier=%q require=%v err=%v; want tier=%q require=%v",
				tc.flag, p.Tier, p.RequireEnclave, err, tc.wantTier, tc.wantRequire)
		}
	}
}

// TestParseSetupArgsConflict: a tier flag and --plaintext together are a usage error
// (intent must not be guessed).
func TestParseSetupArgsConflict(t *testing.T) {
	for _, args := range [][]string{
		{"--plaintext", "--keychain"},
		{"--keychain", "--enclave"},
		{"--enclave", "--require-enclave"},
		{"--require-enclave", "--plaintext"},
	} {
		if _, err := parseSetupArgs(args); err == nil || !strings.Contains(err.Error(), "conflicting") {
			t.Fatalf("%v: err = %v, want a conflicting-tier-flags error", args, err)
		}
	}
}

// TestParseSetupArgsRejectsUnexpected: any non-flag argument is a usage error (setup
// takes no values/positionals).
func TestParseSetupArgsRejectsUnexpected(t *testing.T) {
	if _, err := parseSetupArgs([]string{"--rotate=true"}); err == nil {
		t.Fatal("expected refusal of --rotate=true (flags take no value)")
	}
	_, err := parseSetupArgs([]string{"extra"})
	if err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("err = %v, want an unexpected-argument error", err)
	}
}
