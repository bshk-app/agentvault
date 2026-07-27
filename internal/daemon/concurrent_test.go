package daemon

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// TestNewCreatesMissingParentDir guards a regression: the single-instance lockfile
// sits next to the socket, so New must create the parent dir (0700) before opening
// it. Real avd runs against ~/Library/Caches/agentvault/avd.sock where that dir
// does not exist on first start.
func TestNewCreatesMissingParentDir(t *testing.T) {
	base, err := os.MkdirTemp(shortTempBase(), "avp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	// path's parent ("agentvault") does NOT exist yet.
	path := filepath.Join(base, "agentvault", "avd.sock")

	srv, err := New(path)
	if err != nil {
		t.Fatalf("New with missing parent dir: %v", err)
	}
	defer srv.Close()

	// The dir must EXIST on every platform — that is the regression this test guards.
	// Its 0700 mode is only assertable on Unix: Go reports 0777 for any directory on
	// Windows ($GOROOT/src/os/types_windows.go), so 0700 is not expressible on NTFS.
	if fi, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("parent dir not created: %v", err)
	} else if perm := fi.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o700 {
		t.Fatalf("parent dir perm = %o, want 700", perm)
	}
}

// TestConcurrentNewSingleInstance is the regression test for code-review finding
// I-1 (concurrent-spawn race). The old try-dial-then-Listen guard was not atomic:
// two avd processes starting at once could both pass the dial (nobody listening
// yet) and both Listen, with the second clobbering the first's socket. A
// cross-process flock makes daemon.New atomic, so launching N concurrent New on
// the same path must yield EXACTLY ONE winner; the rest must error.
func TestConcurrentNewSingleInstance(t *testing.T) {
	path := shortSocketPath(t)

	const n = 16
	var (
		wg      sync.WaitGroup
		winners int64
		mu      sync.Mutex
		servers []*Server
	)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			srv, err := New(path)
			if err != nil {
				return
			}
			atomic.AddInt64(&winners, 1)
			mu.Lock()
			servers = append(servers, srv)
			mu.Unlock()
		}()
	}
	wg.Wait()

	for _, srv := range servers {
		srv.Close()
	}

	if got := atomic.LoadInt64(&winners); got != 1 {
		t.Fatalf("concurrent New winners = %d, want exactly 1", got)
	}
}
