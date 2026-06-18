// Package agefile implements an age-encrypted-file Backend. The plaintext is a JSON
// object mapping logical names to secret values. The age identity is injected (Phase 6
// wraps it in the Secure Enclave). Isolated package: keeps filippo.io/age out of av.
package agefile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"github.com/beshkenadze/agentvault/internal/backend"
)

// Backend decrypts an age file on each call and resolves a name -> value lookup.
type Backend struct {
	id   age.Identity
	path string
}

// New returns a backend that decrypts path with id.
func New(id age.Identity, path string) *Backend {
	return &Backend{id: id, path: path}
}

// EncryptVault age-encrypts a name -> value map to w for recipient. It is the inverse
// of load: the plaintext is the JSON object the Backend decrypts. Phase 6's `av add`
// uses it to write the vault; tests use it instead of duplicating the encrypt logic.
func EncryptVault(w io.Writer, recipient age.Recipient, data map[string]string) error {
	plain, err := json.Marshal(data)
	if err != nil {
		return err
	}
	aw, err := age.Encrypt(w, recipient)
	if err != nil {
		return err
	}
	if _, err := aw.Write(plain); err != nil {
		return err
	}
	return aw.Close()
}

func (b *Backend) load() (map[string]string, error) {
	f, err := os.Open(b.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, b.id)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", b.path, err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var data map[string]string
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, fmt.Errorf("parse vault plaintext: %w", err)
	}
	return data, nil
}

func (b *Backend) Resolve(locator string) (backend.Secret, error) {
	data, err := b.load()
	if err != nil {
		return backend.Secret{}, err
	}
	v, ok := data[locator]
	if !ok {
		return backend.Secret{}, backend.ErrNotFound
	}
	return backend.Secret{Value: v}, nil
}

func (b *Backend) List(prefix string) ([]backend.Meta, error) {
	data, err := b.load()
	if err != nil {
		return nil, err
	}
	var out []backend.Meta
	for k := range data {
		if prefix == "" || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			out = append(out, backend.Meta{Locator: k})
		}
	}
	return out, nil
}

// compile-time check that Backend satisfies the interface.
var _ backend.Backend = (*Backend)(nil)
