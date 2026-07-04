//go:build windows

package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func autostart(socketPath string) error {
	_ = socketPath
	bin := os.Getenv("AV_AVD_PATH")
	if bin == "" {
		selfDir := ""
		if self, err := os.Executable(); err == nil {
			selfDir = filepath.Dir(self)
		}
		bin = resolveWindowsAvdPath(selfDir)
	}
	cmd := exec.Command(bin)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	return cmd.Start()
}

func resolveWindowsAvdPath(selfDir string) string {
	if selfDir != "" {
		for _, cand := range []string{
			filepath.Join(selfDir, "avd.exe"),
			filepath.Join(selfDir, "avd"),
		} {
			if executableExists(cand) {
				return cand
			}
		}
	}
	return "avd.exe"
}

func executableExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
