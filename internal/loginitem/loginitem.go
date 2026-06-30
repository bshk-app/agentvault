// Package loginitem registers avd to start at login. Two backends:
// SMAppService (the signed .app, macOS 13+) and a ~/Library/LaunchAgents plist
// (build-from-source). The pure pieces here — State and selectBackend — carry no
// OS calls so they are testable on any platform; the OS work lives in *_darwin.go.
package loginitem

import "strings"

// State is the login-item registration state. SMAppService adds RequiresApproval
// (registered, but the user must flip it on in System Settings); the LaunchAgent
// backend only ever reports Disabled/Enabled.
type State int

const (
	StateDisabled State = iota
	StateEnabled
	StateRequiresApproval
)

func (s State) String() string {
	switch s {
	case StateEnabled:
		return "enabled"
	case StateRequiresApproval:
		return "requires-approval"
	default:
		return "disabled"
	}
}

// Backend names the mechanism a Manager uses (also the wire value in ServiceResult).
type Backend string

const (
	BackendSMAppService Backend = "smappservice"
	BackendLaunchAgent  Backend = "launchagent"
)

// Manager registers/unregisters avd as a login item. Implemented per-backend in
// *_darwin.go; a non-darwin stub returns ErrUnsupported.
type Manager interface {
	Enable() error
	Disable() error
	Status() (State, error)
	Backend() Backend
}

// selectBackend picks the backend from the avd executable path and the macOS major
// version. SMAppService requires BOTH the signed-app bundle layout (the plist is
// sealed in Contents/Library/LaunchAgents) AND macOS >= 13; everything else uses the
// LaunchAgent fallback. Pure so the gate is unit-tested without a real bundle.
func selectBackend(exe string, macOSMajor int) Backend {
	if macOSMajor >= 13 && strings.HasSuffix(exe, ".app/Contents/MacOS/avd") {
		return BackendSMAppService
	}
	return BackendLaunchAgent
}
