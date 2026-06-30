package client

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/beshkenadze/agentvault/internal/envfile"
	"github.com/beshkenadze/agentvault/internal/manifest"
)

// EnvOptions configures a single `av env` invocation.
type EnvOptions struct {
	EnvFilePath  string   // .env to read (default ".env" in cwd)
	Profile      string   // agentvault.yaml profile to merge (default "smoke")
	ManifestPath string   // agentvault.yaml path (default "agentvault.yaml")
	NoMask       bool     // disable layer-1 source masking of the child's output
	Command      []string // child argv (after `--`)
}

const syntheticEnvProfile = "_env"

// EnvRun resolves av:// references from a .env (and/or an agentvault.yaml profile) and
// runs Command with the resolved values + .env literals injected, masking output unless
// NoMask. It reuses the av run engine: refs are merged into one synthetic profile and
// resolved via a single cl.Resolve (one unlock for all normal-tier secrets). Fail-closed:
// if a reference can't resolve, or no source exists, the child is never started.
func EnvRun(cl *Client, opts EnvOptions, stdout, stderr io.Writer) (exitCode int, err error) {
	if len(opts.Command) == 0 {
		return -1, errors.New("av env: no command given (use: av env [--env-file PATH] -- cmd args...)")
	}
	envPath := opts.EnvFilePath
	if envPath == "" {
		envPath = ".env"
	}
	manPath := opts.ManifestPath
	if manPath == "" {
		manPath = defaultManifestPath
	}
	// profile is the agentvault.yaml profile to LOOK UP (default "smoke"). Distinct from
	// syntheticEnvProfile ("_env"), the in-memory profile the merged entries are resolved
	// under — don't conflate the two.
	profile := opts.Profile
	if profile == "" {
		profile = "smoke"
	}

	// Gather .env (optional): literals pass through, refs go into the merge.
	var literals, envRefs map[string]string
	envPresent := fileExists(envPath)
	if envPresent {
		kv, perr := envfile.Parse(envPath)
		if perr != nil {
			return -1, fmt.Errorf("av env: %w", perr)
		}
		envRefs, literals, perr = envfile.Split(kv)
		if perr != nil {
			return -1, fmt.Errorf("av env: %w", perr)
		}
	}

	// Gather the agentvault.yaml profile (optional).
	var yamlProfile manifest.Profile
	manPresent := fileExists(manPath)
	if manPresent {
		m, merr := manifest.Load(manPath)
		if merr != nil {
			return -1, fmt.Errorf("av env: %w", merr)
		}
		p, ok := m.Profile(profile)
		if !ok && !envPresent {
			// yaml is the only source but the chosen profile is absent — fail-closed.
			return -1, fmt.Errorf("av env: profile %q not found in %s", profile, manPath)
		}
		yamlProfile = p // nil when absent-but-.env-present (env refs carry the load)
	}

	if !envPresent && !manPresent {
		return -1, fmt.Errorf("av env: no %s or %s", envPath, manPath)
	}

	// Merge: .env refs (normal tier) + yaml profile entries. A name in both is a hard
	// error (don't guess precedence; don't silently downgrade a dangerous yaml secret).
	entries := make(map[string]manifest.Entry, len(envRefs)+len(yamlProfile))
	for name, e := range yamlProfile {
		entries[name] = e
	}
	for name, ref := range envRefs {
		if _, dup := entries[name]; dup {
			return -1, fmt.Errorf("av env: %q defined in both %s and %s — remove one", name, envPath, manPath)
		}
		entries[name] = manifest.Entry{Ref: ref, Tier: manifest.TierNormal}
	}

	// Resolve (one RPC) unless there is nothing to resolve.
	var vals map[string]string
	if len(entries) > 0 {
		b, berr := manifest.SyntheticProfile(syntheticEnvProfile, entries)
		if berr != nil {
			return -1, fmt.Errorf("av env: build request: %w", berr)
		}
		vals, err = cl.Resolve(syntheticEnvProfile, b)
		if err != nil {
			return -1, err // *ipc.RPCError mapped by cmd/av (locked/denied/bad-request); fail-closed
		}
	}

	return runChild(vals, literals, !opts.NoMask, opts.Command, stdout, stderr)
}

// fileExists reports whether path is a readable regular file.
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
