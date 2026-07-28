package main

import (
	"os"
	"runtime"
	"testing"
)

// requirePerm asserts a file exists and carries the given Unix permission bits.
//
// The MODE half is skipped on Windows: Go can only ever report 0666/0444 for a file
// there ($GOROOT/src/os/types_windows.go), so 0600 and 0755 are not expressible on NTFS.
// The existence half still runs — the stat is deliberately before that early return — so
// a file that was never written still fails on Windows. The production chmods this
// guards are real and load-bearing on Unix; only the assertion is unavailable here.
//
// It lives in its own file because two test files in this package need it (init_test.go
// and sops_import_test.go).
func requirePerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}
