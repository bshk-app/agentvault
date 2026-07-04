//go:build windows

// Package keystore stores AgentVault's age identity in Windows Credential Manager.
package keystore

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/beshkenadze/agentvault/internal/backend"
)

const targetName = "AgentVault/identity"

const (
	credTypeGeneric      = 1
	credPersistLocalMach = 2
)

var (
	advapi32      = windows.NewLazySystemDLL("advapi32.dll")
	procCredWrite = advapi32.NewProc("CredWriteW")
	procCredRead  = advapi32.NewProc("CredReadW")
	procCredFree  = advapi32.NewProc("CredFree")
)

type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

type Store struct{}

func New() *Store { return &Store{} }

func NewWithRunner(_ any) *Store { return &Store{} }

func (s *Store) Store(identity []byte) error {
	value := []byte(strings.TrimRight(string(identity), "\n"))
	target, err := windows.UTF16PtrFromString(targetName)
	if err != nil {
		return err
	}
	user, err := windows.UTF16PtrFromString("agentvault")
	if err != nil {
		return err
	}
	var blob *byte
	if len(value) > 0 {
		blob = &value[0]
	}
	cred := credential{
		Type:               credTypeGeneric,
		TargetName:         target,
		CredentialBlobSize: uint32(len(value)),
		CredentialBlob:     blob,
		Persist:            credPersistLocalMach,
		UserName:           user,
	}
	r1, _, e1 := procCredWrite.Call(uintptr(unsafe.Pointer(&cred)), 0)
	if r1 == 0 {
		return fmt.Errorf("keystore store: %w", e1)
	}
	return nil
}

func (s *Store) Read() ([]byte, error) {
	target, err := windows.UTF16PtrFromString(targetName)
	if err != nil {
		return nil, err
	}
	var pcred *credential
	r1, _, e1 := procCredRead.Call(
		uintptr(unsafe.Pointer(target)),
		credTypeGeneric,
		0,
		uintptr(unsafe.Pointer(&pcred)),
	)
	if r1 == 0 {
		if errors.Is(e1, windows.ERROR_NOT_FOUND) {
			return nil, fmt.Errorf("keystore read: %w", backend.ErrNotFound)
		}
		return nil, fmt.Errorf("keystore read: %w", e1)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pcred)))
	if pcred == nil || pcred.CredentialBlob == nil || pcred.CredentialBlobSize == 0 {
		return nil, fmt.Errorf("keystore read: %w", backend.ErrNotFound)
	}
	b := unsafe.Slice(pcred.CredentialBlob, int(pcred.CredentialBlobSize))
	return append([]byte(nil), b...), nil
}
