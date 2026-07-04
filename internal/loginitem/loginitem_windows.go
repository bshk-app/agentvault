//go:build windows

package loginitem

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const windowsTaskName = `AgentVault avd`

type taskSchedulerManager struct {
	exe string
	run func(name string, args ...string) ([]byte, error)
}

func New() Manager {
	exe, _ := os.Executable()
	return taskSchedulerManager{exe: exe, run: runCommandOutput}
}

func (m taskSchedulerManager) Enable() error {
	exe := m.exe
	if exe == "" {
		exe = "avd.exe"
	}
	_, err := m.run("schtasks.exe",
		"/Create",
		"/TN", windowsTaskName,
		"/TR", quoteWindowsArg(exe),
		"/SC", "ONLOGON",
		"/RL", "LIMITED",
		"/F",
	)
	if err != nil {
		return fmt.Errorf("task scheduler enable: %w", err)
	}
	return nil
}

func (m taskSchedulerManager) Disable() error {
	_, err := m.run("schtasks.exe", "/Delete", "/TN", windowsTaskName, "/F")
	if err != nil {
		return fmt.Errorf("task scheduler disable: %w", err)
	}
	return nil
}

func (m taskSchedulerManager) Status() (State, error) {
	out, err := m.run("schtasks.exe", "/Query", "/TN", windowsTaskName)
	if err != nil {
		return StateDisabled, nil
	}
	if strings.Contains(strings.ToLower(string(out)), strings.ToLower(windowsTaskName)) {
		return StateEnabled, nil
	}
	return StateDisabled, nil
}

func (m taskSchedulerManager) Backend() Backend { return BackendTaskScheduler }

func runCommandOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func quoteWindowsArg(s string) string {
	if strings.ContainsAny(s, " \t\"") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
