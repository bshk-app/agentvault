//go:build linux

package daemon

import (
	"bufio"
	"context"
	"log"
	"os/exec"
	"strings"
	"sync"
)

// StartAutoLock watches logind D-Bus signals through dbus-monitor and locks the session
// on sleep or session-lock signals. If dbus-monitor is unavailable the watcher exits
// fail-soft; TTL-based locking still applies.
func StartAutoLock(s *Session) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "dbus-monitor", "--system", "type='signal',sender='org.freedesktop.login1'")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("agentvault: linux auto-lock disabled: %v", err)
		cancel()
		return func() {}
	}
	if err := cmd.Start(); err != nil {
		log.Printf("agentvault: linux auto-lock disabled: %v", err)
		cancel()
		return func() {}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if shouldAutoLockDBusLine(sc.Text()) {
				s.Lock()
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			_ = cmd.Wait()
			<-done
		})
	}
}

func shouldAutoLockDBusLine(line string) bool {
	return strings.Contains(line, "member=PrepareForSleep") || strings.Contains(line, "member=Lock")
}
