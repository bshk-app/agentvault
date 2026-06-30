//go:build darwin

package loginitem

/*
#cgo LDFLAGS: -framework Foundation -framework ServiceManagement
#include <stdlib.h>
int av_loginitem_register(const char *plistName, char **err);
int av_loginitem_unregister(const char *plistName, char **err);
int av_loginitem_status(const char *plistName);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// plistNameAvd is the bundled LaunchAgent plist sealed at
// AgentVault.app/Contents/Library/LaunchAgents/<this> (see scripts/release-signed.sh).
const plistNameAvd = "app.bshk.agentvault.avd.plist"

type smAppService struct{ plistName string }

func newSMAppService() *smAppService { return &smAppService{plistName: plistNameAvd} }

func (s *smAppService) Backend() Backend { return BackendSMAppService }

// Enable/Disable inline the cgo call (rather than share a helper) because cgo
// cannot pass a C function as a Go-typed value; each duplicates the CString +
// error-string handling. errFromCgo turns the non-zero return + *err into a Go error.
func (s *smAppService) Enable() error {
	cName := C.CString(s.plistName)
	defer C.free(unsafe.Pointer(cName))
	var cErr *C.char
	rc := C.av_loginitem_register(cName, &cErr)
	return errFromCgo(int(rc), cErr)
}

func (s *smAppService) Disable() error {
	cName := C.CString(s.plistName)
	defer C.free(unsafe.Pointer(cName))
	var cErr *C.char
	rc := C.av_loginitem_unregister(cName, &cErr)
	return errFromCgo(int(rc), cErr)
}

// errFromCgo maps a native return code (0 == ok) plus an optional C error string
// (caller-allocated by strdup, freed here) into a Go error. nil on success.
func errFromCgo(rc int, cErr *C.char) error {
	if rc == 0 {
		return nil
	}
	msg := "SMAppService failed"
	if cErr != nil {
		msg = C.GoString(cErr)
		C.free(unsafe.Pointer(cErr))
	}
	return fmt.Errorf("loginitem: %s", msg)
}

func (s *smAppService) Status() (State, error) {
	cName := C.CString(s.plistName)
	defer C.free(unsafe.Pointer(cName))
	switch int(C.av_loginitem_status(cName)) {
	case 1: // SMAppServiceStatusEnabled
		return StateEnabled, nil
	case 2: // SMAppServiceStatusRequiresApproval
		return StateRequiresApproval, nil
	default: // 0 NotRegistered, 3 NotFound
		return StateDisabled, nil
	}
}
