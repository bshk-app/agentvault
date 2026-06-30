package loginitem

import "testing"

func TestStateString(t *testing.T) {
	cases := map[State]string{
		StateDisabled:         "disabled",
		StateEnabled:          "enabled",
		StateRequiresApproval: "requires-approval",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestSelectBackend(t *testing.T) {
	cases := []struct {
		name  string
		exe   string
		major int
		want  Backend
	}{
		{"bundle on ventura", "/Applications/AgentVault.app/Contents/MacOS/avd", 13, BackendSMAppService},
		{"bundle on sonoma", "/Applications/AgentVault.app/Contents/MacOS/avd", 14, BackendSMAppService},
		{"bundle on monterey -> fallback", "/Applications/AgentVault.app/Contents/MacOS/avd", 12, BackendLaunchAgent},
		{"bare binary on ventura -> fallback", "/usr/local/bin/avd", 13, BackendLaunchAgent},
		{"dev binary -> fallback", "/tmp/go-build/avd", 14, BackendLaunchAgent},
	}
	for _, c := range cases {
		if got := selectBackend(c.exe, c.major); got != c.want {
			t.Errorf("%s: selectBackend(%q, %d) = %q, want %q", c.name, c.exe, c.major, got, c.want)
		}
	}
}
