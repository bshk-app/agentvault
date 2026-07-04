//go:build windows

package transport

import "testing"

func TestCheckPeerWindowsRejectsNilConn(t *testing.T) {
	if err := CheckPeer(nil); err == nil {
		t.Fatal("nil connection must be rejected")
	}
}

func TestCheckUIDWindowsPureLogic(t *testing.T) {
	if checkUID(10, 10) != nil {
		t.Fatal("same uid should pass")
	}
	if checkUID(10, 11) == nil {
		t.Fatal("different uid should fail")
	}
}
