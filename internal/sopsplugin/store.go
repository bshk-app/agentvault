package sopsplugin

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend"
)

// Namespace prefixes every SOPS identity stored in the shared vault. Reusing the vault
// rather than opening a second encrypted file means the atomic write, the flock, and the
// encryption in internal/backend/agefile are written once; the prefix is what keeps the
// two populations of secrets apart inside it.
//
// It is the SINGLE source for that prefix: the Store writes it, and `av read` refuses
// names under it. That refusal is the whole reason a private key here cannot be printed
// the way an ordinary secret can, so the two must not drift.
const Namespace = "sops/"

// VaultBackendID names the backend a Store lives in: the local age file vault, registered
// under this id in the daemon's backend registry.
//
// It is exported so that ONE identifier names the backend everywhere. The daemon refuses
// Namespace on resolve/add/rm for THIS backend only — deliberately, because enforcement
// should be exactly as wide as the thing it protects: av://1p/sops/prod/key addresses a
// 1Password vault called "sops" and can hold no AgentVault identity, so refusing it would
// deny a user for nothing. That scoping is only safe while the guard and the Store agree
// on which backend that is.
//
// So the daemon builds its Store from the registry under THIS constant rather than a
// literal. Without it the two are coupled by nothing but a comment in another package,
// and the day someone writes NewStore(keychainBE, …) the guard silently stops covering
// the namespace it exists for — with `av read keychain/sops/x` printing an age private
// key and no test failing.
const VaultBackendID = "file"

// Tier says how often an identity has to prove presence. `normal` spends one presence
// check per command, so a `helm secrets template` over thirty files costs one touch;
// `dangerous` spends one PER FILE, which is deliberately slow — a production deploy should
// be hard to perform absent-mindedly.
//
// The vocabulary matches manifest.Tier and audit.Event.Tier rather than importing either.
// audit already spells it as a bare string for the same reason: manifest is the parser for
// agentvault.yaml, and a stored SOPS identity is not a manifest entry. Keeping the type
// local also keeps a YAML parser out of age-plugin-av, which imports this package.
type Tier string

const (
	TierNormal    Tier = "normal"
	TierDangerous Tier = "dangerous"
)

// Identity is a stored SOPS identity WITH its private key. Get and FindByRecipient are the
// only functions that return one, and they exist precisely to fetch the key; nothing else
// in this package hands one out. Key is age's own type rather than the AGE-SECRET-KEY-1…
// text so the material can be used (Unwrap, Recipient) without ever being rendered.
type Identity struct {
	Name string
	Tier Tier
	Key  *age.X25519Identity
}

// String keeps the private key out of fmt. age.X25519Identity.String() IS the
// AGE-SECRET-KEY-1… text, and fmt applies Stringer to struct fields — so without a String
// method here, a line as ordinary as fmt.Errorf("sops unwrap %v: %w", id, err) would put a
// private key into an error string, and from there into the audit log or a crash dump.
// Defining it on Identity suppresses %v, %+v and %s at once, which is the only way to cover
// call sites this package will never see. Only %#v bypasses a Stringer, and it renders Key
// as a pointer address rather than a key.
func (i Identity) String() string {
	return fmt.Sprintf("sops identity %q (tier %s)", i.Name, i.Tier)
}

// Info is an identity WITHOUT its private key — the view `av sops ls` prints. It carries
// the recipient, which is public by construction, and deliberately has no field that could
// hold key material. Adding one would defeat the namespace.
type Info struct {
	Name      string
	Recipient string
	Tier      Tier
}

// storedIdentity is the JSON envelope held in one vault entry. The vault maps name to a
// single string, so the tier has to travel INSIDE the value: a sibling `sops/<name>.tier`
// entry would be a second write that can diverge from the first, and agefile.Add commits
// one entry at a time, so a crash between them leaves a key with no tier or a tier with no
// key. One envelope is one atomic entry, and it takes new fields without a migration.
type storedIdentity struct {
	Key  string `json:"key"`
	Tier Tier   `json:"tier,omitempty"`
}

// Store keeps SOPS identities in the vault under Namespace. It depends on the backend
// interfaces rather than *agefile.Backend so the daemon can pass the real vault and tests
// can pass a fake — and so the read paths cannot reach a write method at all.
type Store struct {
	reader backend.Backend
	writer backend.Writer
}

// NewStore returns a Store over an existing vault. Both arguments are normally the same
// *agefile.Backend, which implements the read and write halves.
func NewStore(b backend.Backend, w backend.Writer) *Store {
	return &Store{reader: b, writer: w}
}

// ValidateName reports whether name may be stored as a SOPS identity. It is exported
// because the rule has two enforcers and must have ONE definition: Put refuses a bad name
// at the vault (so nothing reaches the store by any route), and the daemon's management
// RPCs call it on the way in — BEFORE they open the session — so a typo is refused for
// free instead of costing a Touch ID, and so an agent on a locked vault is told its name
// is wrong rather than being sent to `av unlock` to retry the same broken request forever.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("sops identity: name must not be empty")
	}
	if strings.Contains(name, "/") {
		// Nothing escapes the namespace — Namespace+name is still under sops/ — but the
		// name would not round-trip: Put("nested/name") stores sops/nested/name, which
		// List reads back with the prefix trimmed as "nested/name", a string `av sops ls`
		// cannot tell apart from a namespace of its own. Refusing keeps one name for one
		// identity everywhere it is printed or typed.
		return fmt.Errorf("sops identity %q: name must not contain a slash", name)
	}
	return nil
}

// NormalizeTier maps a caller's tier onto the two this package knows, defaulting the empty
// one to normal, and rejects anything else. It is the WRITE-side rule and is deliberately
// strict where decode is tolerant: the write is the last moment a typo is cheap to fix —
// `av sops keygen NAME --tier normla` must fail at the prompt rather than store an identity
// whose tier silently reads back as normal months later.
//
// Exported for the same reason as ValidateName: the daemon checks it before spending a
// presence check on a request that was always going to be refused, and Put still enforces
// it, so the two cannot drift apart into two definitions of a valid tier.
//
// SECURITY: the error names the offending tier only. Callers hold key material in the same
// frame and must never wrap it into this.
func NormalizeTier(tier Tier) (Tier, error) {
	switch tier {
	case "":
		return TierNormal, nil
	case TierNormal, TierDangerous:
		return tier, nil
	default:
		return "", fmt.Errorf("invalid tier %q (want %s|%s)", tier, TierNormal, TierDangerous)
	}
}

// Put stores key under name. It takes a parsed *age.X25519Identity, not the key's text, so
// an unparseable key cannot reach the vault and no caller has to handle a bare private-key
// string to use this package.
//
// Name and tier are validated HERE as well as at the RPC edge, and that duplication is the
// point: this is the only door to the vault, so a caller that skips the edge check — a
// test, a future command — still cannot store a nameless identity or an unknown tier.
func (s *Store) Put(name string, key *age.X25519Identity, tier Tier) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	tier, err := NormalizeTier(tier)
	if err != nil {
		// SECURITY: %w carries NormalizeTier's text, which names the tier only. key is in
		// scope and must not appear.
		return fmt.Errorf("sops identity %q: %w", name, err)
	}
	// SECURITY: key.String() is the private key. It goes into the envelope and straight
	// into the vault; it is never logged and never reaches an error from here on.
	value, err := json.Marshal(storedIdentity{Key: key.String(), Tier: tier})
	if err != nil {
		// Unreachable for a struct of strings, and deliberately not wrapped anyway:
		// json's own errors quote the offending value, and the value here is the key.
		return fmt.Errorf("sops identity %q: could not be encoded for storage", name)
	}
	return s.writer.Add(Namespace+name, string(value))
}

// Get returns the identity stored under name, private key included. It is one of the two
// functions in this package that may do that. A name nobody stored returns
// backend.ErrNotFound unchanged, so callers can tell a typo from a real failure.
func (s *Store) Get(name string) (Identity, error) {
	sec, err := s.reader.Resolve(Namespace + name)
	if err != nil {
		return Identity{}, err
	}
	return decode(name, sec.Value)
}

// List returns every stored identity WITHOUT its private key, sorted by name. The sort is
// not cosmetic: the vault is a map, so unsorted output would reorder itself on every
// `av sops ls` against an unchanged vault.
//
// It costs one vault decrypt per identity, because backend.Backend exposes Resolve and
// List and nothing that reads several values at once. That is bounded by how many SOPS
// keys a person has — one or two — and the alternative is a wider backend interface every
// backend would have to implement for this one caller.
func (s *Store) List() ([]Info, error) {
	ids, err := s.each()
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(ids))
	for _, id := range ids {
		// The private key stops here. Only the recipient derived from it goes out.
		out = append(out, Info{Name: id.Name, Recipient: id.Key.Recipient().String(), Tier: id.Tier})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// FindByRecipient returns the identity whose public key is r, or backend.ErrNotFound when
// no stored identity matches. The daemon calls it on every file sops touches, BEFORE
// spending a presence check, so a repo full of files encrypted to other people costs zero
// prompts.
//
// It takes a parsed *age.X25519Recipient on purpose. The recipient arrives from the wire as
// the bech32 "age1…" TEXT of the key (see EncodeIdentity) — base64-of-ASCII once JSON has
// had it — not as 32 raw bytes. A caller comparing raw bytes against that text would never
// match and would report every file as "not yours", so the only way in is through
// age.ParseX25519Recipient and the comparison lives here rather than at each call site.
//
// A corrupt entry elsewhere in the namespace does not fail a lookup that matched. Nothing
// stops `av add sops/notes "reminder"` from landing here, and aborting the scan on it would
// break decryption for every healthy key while `av sops ls` and `av sops recipient` went on
// printing them. So the scan completes, a match wins, and a corrupt entry is reported only
// when nothing matched — corrupt still never masquerades as absent, it just stops taking
// working keys down with it. List stays strict: it is the diagnostic surface.
func (s *Store) FindByRecipient(r *age.X25519Recipient) (Identity, error) {
	if r == nil {
		// A nil recipient matches nothing, which is what ErrNotFound says. The reason to
		// check rather than let it panic: the daemon dispatches each connection as its own
		// goroutine with no recover() above it, so a nil dereference here would not fail
		// one request, it would take avd down for every connected client.
		return Identity{}, backend.ErrNotFound
	}
	ids, corrupt := s.each()
	want := r.String()
	for _, id := range ids {
		// Compare the canonical bech32 text of both sides. Deriving the recipient from
		// the stored key is cheap and keeps the vault free of a public index that could
		// disagree with the keys it indexes.
		if id.Key.Recipient().String() == want {
			return id, nil
		}
	}
	if corrupt != nil {
		return Identity{}, corrupt
	}
	return Identity{}, backend.ErrNotFound
}

// Remove deletes the identity stored under name, returning backend.ErrNotFound if there was
// none. `av sops rm` needs that distinction: it destroys the only copy of a key, and
// reporting success over a mistyped name would leave the user believing a key is gone that
// is still there — or, worse, that the right one was deleted when it was not.
func (s *Store) Remove(name string) error {
	return s.writer.Remove(Namespace + name)
}

// each decodes every identity in the namespace. It is the shared scan behind List and
// FindByRecipient, and it returns BOTH the entries that decoded and the first one that did
// not, because its two callers weigh a corrupt entry differently: List reports it always,
// FindByRecipient only when no healthy key matched.
//
// A corrupt entry is never silently dropped by either. A user whose entry got mangled has
// to be told — an entry that just vanished from `av sops ls` looks exactly like a deleted
// one, and "no identity matched" for a key sitting right there is the worst way to find out.
//
// A Resolve failure is different and still aborts: with one encrypted file behind the whole
// namespace, it means the vault itself is unreadable, so every other entry would fail the
// same way and there is nothing partial to return.
func (s *Store) each() ([]Identity, error) {
	metas, err := s.reader.List(Namespace)
	if err != nil {
		return nil, err
	}
	out := make([]Identity, 0, len(metas))
	var corrupt error
	for _, m := range metas {
		name := strings.TrimPrefix(m.Locator, Namespace)
		sec, err := s.reader.Resolve(m.Locator)
		if err != nil {
			return nil, err
		}
		id, err := decode(name, sec.Value)
		if err != nil {
			if corrupt == nil {
				corrupt = err
			}
			continue
		}
		out = append(out, id)
	}
	return out, corrupt
}

// decode reads one stored value back into an Identity.
//
// Two formats are accepted. The envelope is what Put writes. A bare AGE-SECRET-KEY-1… is
// what a hand-edited vault or an entry predating tiers holds; refusing it would lock a user
// out of a key that is right there, which is worse than assuming the documented default
// tier. A leading "{" tells them apart, so a MALFORMED envelope is an error rather than
// being mistaken for a key and failing later with a stranger message.
//
// A tier that is neither of the two reads as DANGEROUS, and the direction is the whole
// point: dangerous only ever costs extra presence checks, while normal skips them, so
// guessing wrong this way is friction and guessing wrong the other way is a silent
// downgrade. The case that makes it concrete is a third tier introduced in a later release
// and then avd rolled back after a bad deploy — the older binary must not read a tier it
// has never heard of as the cheapest one. An ABSENT or empty tier is not that case: it is
// the pre-tier format, whose documented default is normal, and it stays normal.
//
// SECURITY: value is a private key. Every error here names the identity and stops. age's
// own parse errors are NOT wrapped. The exposure is narrower than that sounds: bech32
// reports the position and value of the FIRST character it rejects and nothing more
// (filippo.io/age/internal/bech32/bech32.go:154,161), e.g. `invalid character data part:
// s[14]=33`, and its caller interpolates that with %v rather than quoting the input
// (x25519.go:145), so the key itself never appears. Not wrapping is still the right call —
// it costs nothing and does not depend on age's error formatting staying where it is.
func decode(name, value string) (Identity, error) {
	// Trimmed once, then used on both paths. A trailing newline is the likeliest artefact
	// of a hand edit, and envelopes already get that tolerance free from encoding/json;
	// parsing the untrimmed value would leave the bare-key path as the only one to reject
	// it.
	value = strings.TrimSpace(value)
	// Pre-seeding Key does double duty. It is the bare-key path's value, and it is also
	// the fallback for an envelope with no "key" field: `{}` unmarshals without touching
	// it, so the entry fails as a key that will not parse rather than as an empty one.
	// Same message either way, one less case to reason about.
	env := storedIdentity{Key: value}
	if strings.HasPrefix(value, "{") {
		if err := json.Unmarshal([]byte(value), &env); err != nil {
			// Not wrapped: json errors quote the offending input.
			return Identity{}, fmt.Errorf("sops identity %q: stored entry is not readable", name)
		}
	}
	key, err := age.ParseX25519Identity(env.Key)
	if err != nil {
		return Identity{}, fmt.Errorf("sops identity %q: stored entry is not a valid age private key", name)
	}
	tier := env.Tier
	switch tier {
	case TierNormal, TierDangerous:
	case "":
		tier = TierNormal
	default:
		tier = TierDangerous
	}
	return Identity{Name: name, Tier: tier, Key: key}, nil
}
