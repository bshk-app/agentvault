package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/backend/agefile"
	"github.com/beshkenadze/agentvault/internal/daemon"
	"github.com/beshkenadze/agentvault/internal/ipc"
)

// nopromptManifest resolves one normal-tier secret off the "file" backend, so a
// successful Resolve proves the daemon session was opened (auto-unlock).
const nopromptManifest = `profiles:
  smoke:
    TOKEN:
      ref: av://file/TOKEN
      tier: normal
`

// nopromptServer wires an in-process daemon whose "file" backend is a seeded age vault
// and whose session is LOCKED but WithUnwrapper — so the client's NoPrompt flag decides
// whether Resolve auto-unlocks (false) or gets CodeLocked (true). It proves the
// env->client->RPC threading end-to-end without spawning a real avd.
func nopromptServer(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := shortDir(t)
	vaultPath := filepath.Join(dir, "vault.age")
	vf, err := os.Create(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := agefile.EncryptVault(vf, id.Recipient(), map[string]string{"TOKEN": "ghp_secret"}); err != nil {
		vf.Close()
		t.Fatal(err)
	}
	if err := vf.Close(); err != nil {
		t.Fatal(err)
	}

	path := shortSocketPath(t)
	srv, err := daemon.New(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := backend.NewRegistry()
	reg.Register("file", agefile.New(agefile.Static{ID: id}, vaultPath))
	// Locked session with an unwrapper: the on-demand unlock path is reachable only when
	// the client does NOT opt out via NoPrompt.
	sess := daemon.NewSession(15 * time.Minute).WithUnwrapper(func() ([]byte, error) {
		return []byte(id.String() + "\n"), nil
	})
	srv.SetResolver(daemon.NewResolver(reg, daemon.NewStubPresence(), sess))
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	return path
}

func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(shortTempBase(), "avnp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// TestResolveNoPromptThreadsToDaemon: WithNoPrompt(true) makes Resolve carry NoPrompt, so
// a locked session returns CodeLocked (the agent's exit-69 pause) instead of auto-unlocking.
func TestResolveNoPromptThreadsToDaemon(t *testing.T) {
	path := nopromptServer(t)
	cl := New(path).WithNoPrompt(true)

	_, err := cl.Resolve("smoke", []byte(nopromptManifest))
	rpc, ok := err.(*ipc.RPCError)
	if !ok || rpc.Code != ipc.CodeLocked {
		t.Fatalf("NoPrompt:true on a locked session must surface CodeLocked, got %v", err)
	}
}

// TestResolveDefaultAutoUnlocks: the default client (NoPrompt false) auto-unlocks a locked
// session with an unwrapper and resolves the value — the interactive on-demand path.
func TestResolveDefaultAutoUnlocks(t *testing.T) {
	path := nopromptServer(t)
	cl := New(path) // default: NoPrompt false

	vals, err := cl.Resolve("smoke", []byte(nopromptManifest))
	if err != nil {
		t.Fatalf("default client should auto-unlock and resolve, got %v", err)
	}
	if vals["TOKEN"] != "ghp_secret" {
		t.Fatalf("resolved TOKEN = %q, want ghp_secret", vals["TOKEN"])
	}
}
