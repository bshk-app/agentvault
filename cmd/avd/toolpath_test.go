package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWithToolDirs(t *testing.T) {
	dirs := []string{"/opt/homebrew/bin", "/usr/local/bin"}
	cases := []struct {
		name, path, want string
	}{
		{"launchd default", "/usr/bin:/bin:/usr/sbin:/sbin", "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"},
		{"already present keeps order", "/opt/homebrew/bin:/usr/bin:/usr/local/bin", "/opt/homebrew/bin:/usr/bin:/usr/local/bin"},
		{"partly present", "/usr/local/bin:/usr/bin", "/usr/local/bin:/usr/bin:/opt/homebrew/bin"},
		{"empty", "", "/opt/homebrew/bin:/usr/local/bin"},
	}
	sep := func(s string) string { return strings.ReplaceAll(s, ":", string(filepath.ListSeparator)) }
	for _, c := range cases {
		if got := withToolDirs(sep(c.path), dirs); got != sep(c.want) {
			t.Errorf("%s: withToolDirs(%q) = %q, want %q", c.name, c.path, got, c.want)
		}
	}
}
