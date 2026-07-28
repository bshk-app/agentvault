package main

import (
	"testing"

	"github.com/beshkenadze/agentvault/internal/ipc"
)

// TestExitForSopsNamespaceRefusal is av's half of the daemon's sops/ namespace refusal.
// The daemon answers `av read sops/mykey` with ipc.CodeBadRequest — proved independently
// over the socket in internal/daemon/sops_namespace_rpc_test.go — and av must surface
// that as exitBadRequest, so a caller can tell "you asked for something you may not have"
// from the generic exit 1 of something breaking.
//
// The check is NOT duplicated on this side, deliberately. `av` is one client of a
// documented local socket, so a guard here would be advice anyone can route around by
// speaking the protocol; and reaching sopsplugin.Namespace from cmd/av would link
// filippo.io/age into the thin client, which TestAvStaysThin forbids. That leaves the
// exit-code mapping as the only av-side link in the chain, which is what this pins.
func TestExitForSopsNamespaceRefusal(t *testing.T) {
	err := &ipc.RPCError{
		Code:    ipc.CodeBadRequest,
		Message: `"sops/mykey" is in the reserved sops/ namespace — use av sops to manage SOPS identities`,
	}
	if got := exitForError(err); got != exitBadRequest {
		t.Fatalf("exitForError(CodeBadRequest) = %d, want exitBadRequest (%d)", got, exitBadRequest)
	}
}
