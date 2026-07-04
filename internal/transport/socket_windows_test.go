//go:build windows

package transport

import (
	"strings"
	"testing"
)

func TestPipeNameFromPathIsStableAndPipeScoped(t *testing.T) {
	a := pipeNameFromPath(`C:\Users\me\AppData\Local\AgentVault\avd.pipe`)
	b := pipeNameFromPath(`c:\users\me\appdata\local\agentvault\avd.pipe`)
	if a != b {
		t.Fatalf("pipe name should be case-normalized: %q != %q", a, b)
	}
	if !strings.HasPrefix(a, `\\.\pipe\agentvault-`) {
		t.Fatalf("pipe name = %q, want agentvault named-pipe prefix", a)
	}
}
