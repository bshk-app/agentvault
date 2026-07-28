package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// sopsKeysFileEnv points sops at an extra keys file. sops opens it *in addition to* the
// user-config-dir file rather than instead of it, so it never moves the write target —
// it only adds a place an existing key may already be sitting.
const sopsKeysFileEnv = "SOPS_AGE_KEY_FILE"

// SopsKeysFilePath is the file sops itself reads age identities from.
//
// This deliberately does not reuse DefaultConfigDir: that resolves AgentVault's own
// directory under AgentVault's rules. This is sops's location under sops's rules, and
// conflating the two fails silently — `av sops import` would write its AGE-PLUGIN-AV
// pointer to a file sops never opens, leaving the user with a bare "no identity
// matched" and no clue why.
func SopsKeysFilePath() string { return sopsKeysFilePath(runtime.GOOS) }

// SopsKeysFileCandidates lists every path that could plausibly hold a keys.txt on this
// platform, most-preferred first, so `av sops import` can name all of them when it finds
// none. SopsKeysFilePath is always one of them.
func SopsKeysFileCandidates() []string { return sopsKeysFileCandidates(runtime.GOOS) }

func sopsKeysFilePath(goos string) string { return sopsKeysFileIn(sopsConfigDirs(goos)[0]) }

func sopsKeysFileCandidates(goos string) []string {
	var paths []string
	// An explicit SOPS_AGE_KEY_FILE is the strongest signal of where the user keeps
	// their key, and a search that only looked at the default location would miss it.
	if p := os.Getenv(sopsKeysFileEnv); p != "" {
		paths = append(paths, p)
	}
	for _, dir := range sopsConfigDirs(goos) {
		paths = append(paths, sopsKeysFileIn(dir))
	}
	return dedupePaths(paths)
}

// sopsKeysFileIn is sops's SopsAgeKeyUserConfigPath joined onto a config directory.
func sopsKeysFileIn(dir string) string { return filepath.Join(dir, "sops", "age", "keys.txt") }

// sopsConfigDirs lists the directories a keys.txt may live in, most-preferred first.
// Element 0 is what sops resolves *when sops can resolve anything at all*, mirroring
// getUserConfigDir in sops/age/keysource.go: sops consults XDG_CONFIG_HOME explicitly
// *only* on darwin, because Go's os.UserConfigDir already honours it on other unixes but
// returns ~/Library/Application Support on macOS and ignores it entirely on Windows.
//
// Where sops can resolve nothing, this still names a path. os.UserConfigDir returns
// ("", error) for a relative XDG_CONFIG_HOME on unix, for an empty %AppData% on Windows,
// and for an unset HOME; sops's `else if userConfigDir != ""` is then false and it opens
// no keys.txt at all, while element 0 here answers confidently. The divergence is
// deliberate: in each of those cases the user's sops is already broken independently of
// AgentVault, and naming the path they would have to fix beats naming none. darwin with
// XDG_CONFIG_HOME set is *not* one of them — sops returns that value raw, without
// os.UserConfigDir's absoluteness check, so passing it through verbatim is exact
// behaviour-matching rather than a shortcut.
//
// goos is a parameter rather than a read of runtime.GOOS so that every platform's branch
// stays reachable from a test on any host; the exported wrappers supply the real one.
func sopsConfigDirs(goos string) []string {
	if goos == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return []string{appData}
		}
		home, _ := os.UserHomeDir()
		return []string{filepath.Join(home, "AppData", "Roaming")}
	}

	var dirs []string
	// sops's darwin branch guards on `ok && userConfigDir != ""` and os.UserConfigDir
	// checks the same emptiness elsewhere, so one non-empty test covers both.
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		dirs = append(dirs, xdg)
	}
	home, _ := os.UserHomeDir()
	if goos == "darwin" {
		dirs = append(dirs, filepath.Join(home, "Library", "Application Support"))
	}
	// Last, and listed on darwin too: sops never reads ~/.config there, but that is
	// where the Linux-oriented docs send people, so a key parked in it has to be
	// reported or its owner never learns why sops ignores it.
	return append(dirs, filepath.Join(home, ".config"))
}

func dedupePaths(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
