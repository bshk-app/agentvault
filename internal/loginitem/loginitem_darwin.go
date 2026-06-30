//go:build darwin

package loginitem

import "os"

/*
#include <sys/utsname.h>
*/
import "C"
import (
	"strconv"
	"strings"
)

// New returns the login-item Manager for this install: SMAppService when avd runs
// from a signed .app on macOS 13+, else the ~/Library/LaunchAgents fallback.
func New() Manager {
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	switch selectBackend(exe, macOSMajor()) {
	case BackendSMAppService:
		return newSMAppService()
	default:
		return newLaunchAgent(exe)
	}
}

// macOSMajor returns the Darwin-to-macOS major version (Darwin 22 == macOS 13).
// uname release "22.x.x" -> 13. Returns 0 if it can't parse (forces the fallback).
func macOSMajor() int {
	var u C.struct_utsname
	if C.uname(&u) != 0 {
		return 0
	}
	rel := C.GoString(&u.release[0])
	darwin, err := strconv.Atoi(strings.SplitN(rel, ".", 2)[0])
	if err != nil || darwin < 9 {
		return 0
	}
	return darwin - 9 // Darwin 22 -> macOS 13
}
