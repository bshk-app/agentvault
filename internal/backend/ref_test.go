package backend

import "testing"

func TestParseRef(t *testing.T) {
	cases := []struct {
		in      string
		wantBE  string
		wantLoc string
	}{
		{"av://1p/Eng/GitHub CI/token", "1p", "Eng/GitHub CI/token"},
		{"av://file/GITHUB_TOKEN", "file", "GITHUB_TOKEN"},
		{"av://keychain/av/STRIPE", "keychain", "av/STRIPE"},
	}
	for _, c := range cases {
		ref, err := ParseRef(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if ref.Backend != c.wantBE || ref.Locator != c.wantLoc {
			t.Errorf("%s -> %+v, want backend=%q locator=%q", c.in, ref, c.wantBE, c.wantLoc)
		}
	}
}

func TestParseRefRejectsBad(t *testing.T) {
	for _, bad := range []string{"", "1p/x", "http://x/y", "av://", "av://onlybackend"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
