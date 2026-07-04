//go:build linux

package loginitem

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

const linuxUnitName = "app.bshk.agentvault.avd.service"

type systemdUserManager struct {
	exe string
	run func(name string, args ...string) error
}

func New() Manager {
	exe, _ := os.Executable()
	return systemdUserManager{exe: exe, run: runCommand}
}

func (m systemdUserManager) Enable() error {
	unitPath, err := m.writeUnit()
	if err != nil {
		return err
	}
	if err := m.run("systemctl", "--user", "daemon-reload"); err != nil {
		return fmt.Errorf("systemd daemon-reload (%s): %w", unitPath, err)
	}
	if err := m.run("systemctl", "--user", "enable", "--now", linuxUnitName); err != nil {
		return fmt.Errorf("systemd enable: %w", err)
	}
	return nil
}

func (m systemdUserManager) Disable() error {
	if err := m.run("systemctl", "--user", "disable", "--now", linuxUnitName); err != nil {
		return fmt.Errorf("systemd disable: %w", err)
	}
	return nil
}

func (m systemdUserManager) Status() (State, error) {
	if err := m.run("systemctl", "--user", "is-enabled", "--quiet", linuxUnitName); err != nil {
		return StateDisabled, nil
	}
	return StateEnabled, nil
}

func (m systemdUserManager) Backend() Backend { return BackendSystemdUser }

func (m systemdUserManager) writeUnit() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	unitDir := filepath.Join(dir, "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(unitDir, linuxUnitName)
	exe := m.exe
	if exe == "" {
		exe = "avd"
	}
	body := fmt.Sprintf(`[Unit]
Description=AgentVault daemon

[Service]
Type=simple
ExecStart=%s
Restart=on-failure

[Install]
WantedBy=default.target
`, systemdQuote(exe))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func runCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func systemdQuote(s string) string {
	return strconv.Quote(s)
}
