package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/beshkenadze/agentvault/internal/ipc"
	"github.com/beshkenadze/agentvault/internal/transport"
)

// TestResolveRPCRateLimited drives a single resolve whose profile issues more than
// maxIssuancesPerWindow normal-tier secrets, so the limiter trips mid-loop. Over the
// socket the daemon must map ErrRateLimited to CodeRateLimited, return no result, and
// (defense) the session must be relocked. The error message must carry no value.
func TestResolveRPCRateLimited(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")

	yaml, data := manyNormalManifest(maxIssuancesPerWindow + 3)

	path := shortSocketPath(t)
	srv, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	reg := backend.NewRegistry()
	reg.Register("mock", mockBE{data: data})
	sess := NewSession(15 * time.Minute)
	sess.Unlock(15 * time.Minute)
	srv.SetResolver(NewResolver(reg, NewStubPresence(), sess))
	go srv.Serve()

	c, err := transport.Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	params, _ := json.Marshal(ipc.ResolveParams{Profile: "burst", Manifest: []byte(yaml)})
	if err := ipc.NewEncoder(c).Encode(ipc.Request{ID: 1, Method: "resolve", Params: params}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.Response
	if err := ipc.NewDecoder(c).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.Error == nil || resp.Error.Code != ipc.CodeRateLimited {
		t.Fatalf("want CodeRateLimited, got error=%+v result=%s", resp.Error, resp.Result)
	}
	if resp.Result != nil {
		t.Fatalf("rate-limited resolve must not return a result, got %s", resp.Result)
	}
	for _, v := range data {
		if containsStr(resp.Error.Message, v) {
			t.Fatalf("SECURITY: rate-limit error leaked a secret value: %q", resp.Error.Message)
		}
	}
	if !sess.Locked() {
		t.Fatal("session must be relocked after a rate-limit trip over RPC")
	}
}
