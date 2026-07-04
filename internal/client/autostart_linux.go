//go:build linux

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
		bin = resolveLinuxAvdPath(selfDir)
	}
	cmd := exec.Command(bin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	return cmd.Start()
}

func resolveLinuxAvdPath(selfDir string) string {
	if selfDir != "" {
		if cand := filepath.Join(selfDir, "avd"); executableExists(cand) {
			return cand
		}
	}
	return "avd"
}

func executableExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
