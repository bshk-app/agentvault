package main

import "testing"

// TestParseReadArgs covers the symmetry fix: `av read` defaults to DIRECT mode
// against the writable backend (--backend file), so a value added with `av add NAME`
// reads back with `av read NAME` and no agentvault.yaml. --profile switches to
// MANIFEST mode; --backend and --profile are mutually exclusive.
func TestParseReadArgs(t *testing.T) {
	t.Run("default is direct file read (no profile)", func(t *testing.T) {
		profile, backend := "", "file"
		name, err := parseReadArgs([]string{"GITEA_TOKEN"}, &profile, &backend)
		if err != nil {
			t.Fatal(err)
		}
		if name != "GITEA_TOKEN" {
			t.Errorf("name = %q, want GITEA_TOKEN", name)
		}
		if profile != "" {
			t.Errorf("profile = %q, want empty (direct mode is the default)", profile)
		}
		if backend != "file" {
			t.Errorf("backend = %q, want file", backend)
		}
	})

	t.Run("--backend selects the direct backend", func(t *testing.T) {
		profile, backend := "", "file"
		name, err := parseReadArgs([]string{"--backend", "keychain", "K"}, &profile, &backend)
		if err != nil {
			t.Fatal(err)
		}
		if name != "K" || backend != "keychain" || profile != "" {
			t.Errorf("name=%q backend=%q profile=%q", name, backend, profile)
		}
	})

	t.Run("--profile switches to manifest mode", func(t *testing.T) {
		profile, backend := "", "file"
		name, err := parseReadArgs([]string{"--profile", "smoke", "SECRET"}, &profile, &backend)
		if err != nil {
			t.Fatal(err)
		}
		if name != "SECRET" || profile != "smoke" {
			t.Errorf("name=%q profile=%q", name, profile)
		}
	})

	t.Run("--backend and --profile are mutually exclusive", func(t *testing.T) {
		profile, backend := "", "file"
		if _, err := parseReadArgs([]string{"--backend", "file", "--profile", "smoke", "X"}, &profile, &backend); err == nil {
			t.Fatal("expected an error when both --backend and --profile are given")
		}
	})

	t.Run("missing NAME errors", func(t *testing.T) {
		profile, backend := "", "file"
		if _, err := parseReadArgs([]string{}, &profile, &backend); err == nil {
			t.Fatal("expected an error for a missing NAME")
		}
	})
}
