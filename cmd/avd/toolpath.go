package main

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// darwinToolDirs are where Homebrew installs the backend CLIs (op, bw) on Apple
// silicon and Intel Macs. launchd starts avd at login with only
// /usr/bin:/bin:/usr/sbin:/sbin, so without these exec.Command("op") fails with
// "executable file not found in $PATH".
var darwinToolDirs = []string{"/opt/homebrew/bin", "/usr/local/bin"}

// ensureToolPath appends darwinToolDirs to avd's PATH when they are missing.
func ensureToolPath() {
	if runtime.GOOS != "darwin" {
		return
	}
	_ = os.Setenv("PATH", withToolDirs(os.Getenv("PATH"), darwinToolDirs))
}

// withToolDirs appends each dir not already in path, keeping the existing order so
// the user's own PATH still wins.
func withToolDirs(path string, dirs []string) string {
	var parts []string
	if path != "" {
		parts = strings.Split(path, string(filepath.ListSeparator))
	}
	for _, d := range dirs {
		if !slices.Contains(parts, d) {
			parts = append(parts, d)
		}
	}
	return strings.Join(parts, string(filepath.ListSeparator))
}
