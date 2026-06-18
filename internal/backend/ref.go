package backend

import (
	"fmt"
	"strings"
)

// Ref is a parsed av:// reference: a backend id and a backend-specific locator.
type Ref struct {
	Backend string
	Locator string
}

const scheme = "av://"

// ParseRef parses "av://<backend>/<locator...>". The locator may contain slashes
// and spaces; only the first path segment is the backend id.
func ParseRef(s string) (Ref, error) {
	if !strings.HasPrefix(s, scheme) {
		return Ref{}, fmt.Errorf("not an av:// reference: %q", s)
	}
	rest := strings.TrimPrefix(s, scheme)
	be, loc, ok := strings.Cut(rest, "/")
	if !ok || be == "" || loc == "" {
		return Ref{}, fmt.Errorf("malformed reference (want av://backend/locator): %q", s)
	}
	return Ref{Backend: be, Locator: loc}, nil
}
