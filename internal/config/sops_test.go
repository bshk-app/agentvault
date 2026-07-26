package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// Fixed, obviously-fake roots so a failure reads as a path comparison rather than a
// diff of two anonymous temp directories.
const (
	testHome    = "/tmp/av-sops-home"
	testXDG     = "/tmp/av-sops-xdg"
	testAppData = `C:\Users\me\AppData\Roaming`
	testKeyFile = "/tmp/av-sops-explicit/keys.txt"
)

// keysUnder spells out sops's SopsAgeKeyUserConfigPath so the expectations are written
// independently of the join helper under test.
func keysUnder(dir string) string { return filepath.Join(dir, "sops", "age", "keys.txt") }

// setSopsEnv drives every variable sops's lookup consults. xdgSet distinguishes "unset"
// from "set to the empty string": sops's darwin branch guards on `ok && != ""`, so both
// must resolve the same way, and only an explicit unset exercises the first half.
func setSopsEnv(t *testing.T, xdg string, xdgSet bool, keyFile string) {
	t.Helper()
	t.Setenv("HOME", testHome)
	// os.UserHomeDir reads USERPROFILE on Windows, not HOME. This file has no build tag
	// (unlike paths_test.go), so it compiles and runs on a Windows host, where leaving
	// USERPROFILE alone would resolve every fallback against the real user's home.
	t.Setenv("USERPROFILE", testHome)
	t.Setenv("APPDATA", testAppData)
	// t.Setenv runs first even when the goal is to unset — it is what registers the
	// restore at cleanup; os.Unsetenv alone would leak into the next test.
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if !xdgSet {
		os.Unsetenv("XDG_CONFIG_HOME")
	}
	t.Setenv("SOPS_AGE_KEY_FILE", keyFile)
	if keyFile == "" {
		os.Unsetenv("SOPS_AGE_KEY_FILE")
	}
}

// TestSopsKeysFilePath pins the file sops itself opens on each platform, mirroring
// getUserConfigDir in sops/age/keysource.go. A wrong answer here fails silently:
// `av sops import` would write its pointer to a file sops never reads, and the user
// would see only "no identity matched" with nothing to point them at the cause.
//
// The windows rows run on any host. filepath.Join uses the host separator, so the
// assertion is about which directory is chosen — separators are filepath's problem,
// and `make cross-test` compiles this for windows.
func TestSopsKeysFilePath(t *testing.T) {
	cases := []struct {
		name         string
		goos         string
		xdg          string
		xdgSet       bool
		appDataUnset bool
		want         string
	}{
		{"linux honours XDG_CONFIG_HOME", "linux", testXDG, true, false, keysUnder(testXDG)},
		{"linux falls back to ~/.config", "linux", "", false, false, keysUnder(filepath.Join(testHome, ".config"))},
		{"linux treats an empty XDG_CONFIG_HOME as unset", "linux", "", true, false, keysUnder(filepath.Join(testHome, ".config"))},
		{"darwin honours XDG_CONFIG_HOME", "darwin", testXDG, true, false, keysUnder(testXDG)},
		// The non-obvious row: os.UserConfigDir on macOS is ~/Library/Application
		// Support, not ~/.config, and sops joins keys.txt onto that.
		{"darwin falls back to Application Support", "darwin", "", false, false, keysUnder(filepath.Join(testHome, "Library", "Application Support"))},
		{"darwin treats an empty XDG_CONFIG_HOME as unset", "darwin", "", true, false, keysUnder(filepath.Join(testHome, "Library", "Application Support"))},
		// sops checks XDG_CONFIG_HOME explicitly only on darwin, and os.UserConfigDir
		// ignores it on Windows, so %AppData% wins even with XDG_CONFIG_HOME set.
		{"windows ignores XDG_CONFIG_HOME", "windows", testXDG, true, false, keysUnder(testAppData)},
		// os.UserConfigDir errors out when %AppData% is empty rather than falling back,
		// so this branch has no upstream counterpart to mirror — the answer is ours, and
		// being ours is exactly why it needs pinning.
		{"windows without APPDATA falls back under the profile", "windows", "", false, true, keysUnder(filepath.Join(testHome, "AppData", "Roaming"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setSopsEnv(t, c.xdg, c.xdgSet, "")
			if c.appDataUnset {
				// setSopsEnv's t.Setenv already registered the restore; this only has
				// to clear the value for the duration of the subtest.
				os.Unsetenv("APPDATA")
			}
			if got := sopsKeysFilePath(c.goos); got != c.want {
				t.Fatalf("sopsKeysFilePath(%q) = %q, want %q", c.goos, got, c.want)
			}
		})
	}
}

// TestSopsKeysFileCandidates covers the list `av sops import` reports when it finds no
// key. Reporting only the winner strands the two users most likely to need help: the
// macOS user whose key sits in ~/.config because that is what the docs said, and the
// user who set SOPS_AGE_KEY_FILE.
func TestSopsKeysFileCandidates(t *testing.T) {
	appSupport := filepath.Join(testHome, "Library", "Application Support")
	dotConfig := filepath.Join(testHome, ".config")

	cases := []struct {
		name    string
		goos    string
		xdg     string
		xdgSet  bool
		keyFile string
		want    []string
	}{
		{
			name: "linux without XDG_CONFIG_HOME",
			goos: "linux",
			want: []string{keysUnder(dotConfig)},
		},
		{
			name: "linux with XDG_CONFIG_HOME lists the default too", goos: "linux",
			xdg: testXDG, xdgSet: true,
			want: []string{keysUnder(testXDG), keysUnder(dotConfig)},
		},
		{
			name: "an XDG_CONFIG_HOME equal to the default is not listed twice", goos: "linux",
			xdg: dotConfig, xdgSet: true,
			want: []string{keysUnder(dotConfig)},
		},
		{
			// sops never reads ~/.config on macOS, but that is where a user following
			// the Linux-oriented docs put their key, so it has to be reported.
			name: "darwin lists Application Support then ~/.config",
			goos: "darwin",
			want: []string{keysUnder(appSupport), keysUnder(dotConfig)},
		},
		{
			name: "darwin with XDG_CONFIG_HOME puts the winner first", goos: "darwin",
			xdg: testXDG, xdgSet: true,
			want: []string{keysUnder(testXDG), keysUnder(appSupport), keysUnder(dotConfig)},
		},
		{
			// sops opens SOPS_AGE_KEY_FILE in addition to the config-dir file, so both
			// are live locations and both must be reported.
			name: "SOPS_AGE_KEY_FILE is checked first", goos: "linux",
			keyFile: testKeyFile,
			want:    []string{testKeyFile, keysUnder(dotConfig)},
		},
		{
			name: "windows",
			goos: "windows",
			want: []string{keysUnder(testAppData)},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setSopsEnv(t, c.xdg, c.xdgSet, c.keyFile)
			if got := sopsKeysFileCandidates(c.goos); !slices.Equal(got, c.want) {
				t.Fatalf("sopsKeysFileCandidates(%q) = %q, want %q", c.goos, got, c.want)
			}
		})
	}
}

// TestSopsKeysFilePathIsAlwaysACandidate is the invariant `av sops import` leans on: it
// writes to SopsKeysFilePath and reports SopsKeysFileCandidates, so a path that is
// written but never listed would make the failure message actively misleading.
func TestSopsKeysFilePathIsAlwaysACandidate(t *testing.T) {
	for _, keyFile := range []string{"", testKeyFile} {
		setSopsEnv(t, "", false, keyFile)
		if got, cands := SopsKeysFilePath(), SopsKeysFileCandidates(); !slices.Contains(cands, got) {
			t.Fatalf("SOPS_AGE_KEY_FILE=%q: SopsKeysFilePath %q missing from candidates %q", keyFile, got, cands)
		}
	}
}

// TestSopsKeysFilePathUsesRuntimeGOOS keeps the exported wrappers wired to the real
// platform — the parameterised helpers are only reachable from tests, so nothing else
// would catch a wrapper hardcoded to the wrong GOOS.
func TestSopsKeysFilePathUsesRuntimeGOOS(t *testing.T) {
	setSopsEnv(t, testXDG, true, "")
	if got, want := SopsKeysFilePath(), sopsKeysFilePath(runtime.GOOS); got != want {
		t.Fatalf("SopsKeysFilePath = %q, want %q", got, want)
	}
	if got, want := SopsKeysFileCandidates(), sopsKeysFileCandidates(runtime.GOOS); !slices.Equal(got, want) {
		t.Fatalf("SopsKeysFileCandidates = %q, want %q", got, want)
	}
}
