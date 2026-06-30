package manifest

import "testing"

// TestSynthetic builds a one-entry manifest in memory (the direct-addressing path
// used by `av read --backend` and, later, `av env` — resolve a ref with no on-disk
// agentvault.yaml) and proves it round-trips through Parse with the entry intact.
func TestSynthetic(t *testing.T) {
	b, err := Synthetic("_read", "GITEA_TOKEN", "av://file/GITEA_TOKEN", TierNormal)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse(Synthetic()) failed: %v\n%s", err, b)
	}
	p, ok := m.Profile("_read")
	if !ok {
		t.Fatalf("profile _read missing; got %v", m.Profiles)
	}
	e, ok := p["GITEA_TOKEN"]
	if !ok {
		t.Fatalf("entry GITEA_TOKEN missing; got %v", p)
	}
	if e.Ref != "av://file/GITEA_TOKEN" || e.Tier != TierNormal {
		t.Errorf("entry = %+v, want ref=av://file/GITEA_TOKEN tier=normal", e)
	}
}

// TestSyntheticProfile builds a multi-entry profile and proves it round-trips through
// Parse with each entry + tier intact (the path av env uses to resolve a merged set).
func TestSyntheticProfile(t *testing.T) {
	b, err := SyntheticProfile("_env", map[string]Entry{
		"OPENAI_API_KEY": {Ref: "av://file/OPENAI_API_KEY", Tier: TierNormal},
		"STRIPE":         {Ref: "av://keychain/stripe/live", Tier: TierDangerous},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse(SyntheticProfile()) failed: %v\n%s", err, b)
	}
	p, ok := m.Profile("_env")
	if !ok {
		t.Fatalf("profile _env missing; got %v", m.Profiles)
	}
	if p["OPENAI_API_KEY"].Ref != "av://file/OPENAI_API_KEY" || p["OPENAI_API_KEY"].Tier != TierNormal {
		t.Errorf("OPENAI_API_KEY = %+v", p["OPENAI_API_KEY"])
	}
	if p["STRIPE"].Tier != TierDangerous {
		t.Errorf("STRIPE tier = %q, want dangerous", p["STRIPE"].Tier)
	}
}
