//go:build darwin

package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// autostart launches avd detached so it outlives the short-lived av process. It
// locates the avd binary via AV_AVD_PATH (test/override), else as a sibling of the
// running av binary, else "avd" on PATH. The child gets its own session
// (Setsid) and nil stdio so it is fully decoupled from the agent; we Start without
// Wait. The socketPath argument is unused for now (avd resolves its own default
// path) but kept for a future explicit handoff.
func autostart(socketPath string) error {
	_ = socketPath
	bin := os.Getenv("AV_AVD_PATH")
	if bin == "" {
		selfDir := ""
		if self, err := os.Executable(); err == nil {
			selfDir = filepath.Dir(self)
		}
		bin = resolveAvdPath(selfDir, appBundleDirs())
	}
	cmd := exec.Command(bin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	return cmd.Start() // detached: do not Wait
}

// appBundleDirs are the standard macOS locations a Homebrew cask installs
// AgentVault.app to. The cask splits the payload: `binary "av"` symlinks av into the
// brew bin, while `app "AgentVault.app"` moves the bundle to /Applications (or
// ~/Applications for a user-scoped install) — so av is NOT co-located with avd, and
// these absolute locations are how autostart finds avd on a cask install.
func appBundleDirs() []string {
	dirs := []string{"/Applications"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	return dirs
}

// resolveAvdPath finds the avd binary. Order: a sibling `avd` (dev / formula layout),
// a co-located AgentVault.app (unpacked-tarball dir), then the cask app-bundle
// locations in appDirs (/Applications, ~/Applications), else "avd" on PATH. Pure
// (selfDir + appDirs injected) so the candidate order is unit-testable without
// touching the real /Applications. An empty selfDir skips the sibling candidates.
func resolveAvdPath(selfDir string, appDirs []string) string {
	var cands []string
	if selfDir != "" {
		cands = append(cands,
			filepath.Join(selfDir, "avd"),
			filepath.Join(selfDir, "AgentVault.app", "Contents", "MacOS", "avd"),
		)
	}
	for _, d := range appDirs {
		cands = append(cands, filepath.Join(d, "AgentVault.app", "Contents", "MacOS", "avd"))
	}
	for _, cand := range cands {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return "avd" // PATH
}
