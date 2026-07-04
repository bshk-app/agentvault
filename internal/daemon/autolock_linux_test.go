//go:build linux

package daemon

import "testing"

func TestShouldAutoLockDBusLine(t *testing.T) {
	for _, line := range []string{
		"signal time=1 sender=:1.1 -> destination=(null destination) serial=1 path=/org/freedesktop/login1; interface=org.freedesktop.login1.Manager; member=PrepareForSleep",
		"signal time=1 sender=:1.1 -> destination=(null destination) serial=2 path=/org/freedesktop/login1/session/_32; interface=org.freedesktop.login1.Session; member=Lock",
	} {
		if !shouldAutoLockDBusLine(line) {
			t.Fatalf("line should trigger auto-lock: %s", line)
		}
	}
	if shouldAutoLockDBusLine("member=Unlock") {
		t.Fatal("Unlock signal must not trigger auto-lock")
	}
}
