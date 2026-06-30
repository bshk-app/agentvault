// Package envfile parses a .env into KEY=VALUE pairs and splits AgentVault av://
// references from plain literals. It holds no secret values — references are
// locators, literals are non-secret config. Used by `av env`.
package envfile

import (
	"fmt"
	"strings"

	"github.com/beshkenadze/agentvault/internal/backend"
	"github.com/joho/godotenv"
)

// Parse reads a .env at path into a flat KEY=VALUE map (godotenv handles comments,
// quotes, multiline, and the `export ` prefix). A missing/unreadable file is an error
// the caller maps (av env falls back to agentvault.yaml when .env is absent).
func Parse(path string) (map[string]string, error) {
	return godotenv.Read(path)
}

// Split partitions parsed .env pairs into AgentVault references (value is a valid
// av:// reference) and literals (everything else, injected verbatim). A value that
// starts with the av:// scheme but fails to parse is a HARD ERROR naming the key —
// fail-closed, so a typo'd reference never reaches the child as a literal string.
func Split(kv map[string]string) (refs map[string]string, literals map[string]string, err error) {
	refs = make(map[string]string)
	literals = make(map[string]string)
	for k, v := range kv {
		if strings.HasPrefix(v, "av://") {
			if _, perr := backend.ParseRef(v); perr != nil {
				return nil, nil, fmt.Errorf("%s: malformed reference %q: %w", k, v, perr)
			}
			refs[k] = v
			continue
		}
		literals[k] = v
	}
	return refs, literals, nil
}
