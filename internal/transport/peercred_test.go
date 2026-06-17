package transport

import (
	"os"
	"testing"
)

func TestPeerUIDSelf(t *testing.T) {
	path := shortSocketPath(t)
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan uint32, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		uid, err := PeerUID(c)
		if err != nil {
			t.Errorf("PeerUID: %v", err)
			got <- ^uint32(0)
			return
		}
		got <- uid
	}()

	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if uid := <-got; uid != uint32(os.Getuid()) {
		t.Fatalf("peer uid = %d, want %d", uid, os.Getuid())
	}
}

func TestCheckPeerRejectsOtherUID(t *testing.T) {
	// Pure logic: a different uid must be rejected.
	if checkUID(uint32(os.Getuid())+1, uint32(os.Getuid())) == nil {
		t.Fatal("expected rejection for mismatched uid")
	}
	if err := checkUID(uint32(os.Getuid()), uint32(os.Getuid())); err != nil {
		t.Fatalf("same uid should pass: %v", err)
	}
}
