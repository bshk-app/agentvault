package daemon

import (
	"testing"

	"github.com/beshkenadze/agentvault/internal/manifest"
)

func TestStubAuthorizerRequiresEnv(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "")
	a := NewStubAuthorizer()
	if err := a.Authorize(manifest.TierNormal, "X"); err == nil {
		t.Fatal("without AV_TEST_AUTH=allow, authorize must fail")
	}
}

func TestStubAuthorizerAllows(t *testing.T) {
	t.Setenv("AV_TEST_AUTH", "allow")
	a := NewStubAuthorizer()
	if err := a.Authorize(manifest.TierNormal, "X"); err != nil {
		t.Fatalf("with AV_TEST_AUTH=allow, authorize must pass: %v", err)
	}
	if err := a.Authorize(manifest.TierDangerous, "Y"); err != nil {
		t.Fatalf("stub authorizes dangerous too (real prompt is Phase 5): %v", err)
	}
}
