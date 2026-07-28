// Command smoke-seed bootstraps an isolated age-file vault by hand: it generates an age
// identity and writes an age-encrypted vault of NAME=VALUE pairs. It reuses
// agefile.EncryptVault so the on-disk format always matches what avd reads.
//
// It was written for the shell smoke harness, which is no longer part of this repository;
// nothing in the tree calls it today. It is kept as a manual helper for standing up a
// throwaway vault when checking a real toolchain by hand.
//
// NOT shipped: the Homebrew formula builds only av+avd. This is a dev helper.
package main

import (
	"fmt"
	"os"
	"strings"

	"filippo.io/age"

	"github.com/beshkenadze/agentvault/internal/backend/agefile"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: smoke-seed <id-path> <vault-path> [NAME=VALUE ...]")
		os.Exit(2)
	}
	idPath, vaultPath := os.Args[1], os.Args[2]

	id, err := age.GenerateX25519Identity()
	if err != nil {
		fatal(err)
	}
	// The identity file is the plaintext fallback avd loads via AV_AGE_IDENTITY.
	if err := os.WriteFile(idPath, []byte(id.String()+"\n"), 0o600); err != nil {
		fatal(err)
	}

	data := map[string]string{}
	for _, kv := range os.Args[3:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			fatal(fmt.Errorf("bad NAME=VALUE: %q", kv))
		}
		data[k] = v
	}

	f, err := os.OpenFile(vaultPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	if err := agefile.EncryptVault(f, id.Recipient(), data); err != nil {
		fatal(err)
	}
	fmt.Printf("seeded %d entry(ies) into %s\n", len(data), vaultPath)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "smoke-seed:", err)
	os.Exit(1)
}
