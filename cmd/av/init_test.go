package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseInitArgsDefaults: `av init --agent claude-code` defaults the target dir to
// "." (cwd) and force to false.
func TestParseInitArgsDefaults(t *testing.T) {
	opt, err := parseInitArgs([]string{"--agent", "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.agent != "claude-code" {
		t.Errorf("agent = %q, want claude-code", opt.agent)
	}
	if opt.dir != "." {
		t.Errorf("dir = %q, want . (cwd default)", opt.dir)
	}
	if opt.force {
		t.Error("force should default to false")
	}
}

// TestParseInitArgsDirAndForce: --dir and --force are parsed; --agent=X form works.
func TestParseInitArgsDirAndForce(t *testing.T) {
	opt, err := parseInitArgs([]string{"--agent=generic", "--dir", "/tmp/x", "--force"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.agent != "generic" || opt.dir != "/tmp/x" || !opt.force {
		t.Fatalf("got %+v", opt)
	}
}

// TestParseInitArgsNeedsAgent: a missing --agent is a usage error.
func TestParseInitArgsNeedsAgent(t *testing.T) {
	if _, err := parseInitArgs([]string{"--dir", "/tmp/x"}); err == nil {
		t.Fatal("expected an error when --agent is missing")
	}
}

// TestInitClaudeCodeWritesFiles: end-to-end, doInit for claude-code into a tmp dir
// writes the hook script (0755, contains "av scrub", starts with a shebang), the
// skill doc (mentions av run / av scrub / {{AV:NAME}} opaque / coverage contract),
// and the hooks snippet.
func TestInitClaudeCodeWritesFiles(t *testing.T) {
	dir := t.TempDir()
	if err := doInit(initOptions{agent: "claude-code", dir: dir}); err != nil {
		t.Fatal(err)
	}

	hookPath := filepath.Join(dir, ".claude/hooks/av-scrub.sh")
	requirePerm(t, hookPath, 0o755)
	hook, _ := os.ReadFile(hookPath)
	if !strings.HasPrefix(string(hook), "#!") {
		t.Error("hook must start with a shebang")
	}
	if !strings.Contains(string(hook), "av scrub") {
		t.Error("hook must pipe through `av scrub`")
	}

	skill, err := os.ReadFile(filepath.Join(dir, ".claude/skills/agentvault/SKILL.md"))
	if err != nil {
		t.Fatalf("skill doc not written: %v", err)
	}
	for _, want := range []string{"av run", "av scrub", "{{AV:NAME}}", "opaque", "Bash", "MCP", "av read"} {
		if !strings.Contains(string(skill), want) {
			t.Errorf("skill doc missing %q", want)
		}
	}

	if _, err := os.Stat(filepath.Join(dir, ".claude/agentvault.hooks.json")); err != nil {
		t.Errorf("hooks snippet not written: %v", err)
	}
}

// TestInitGenericWritesFiles: the generic variant writes a hook + doc (no .claude path).
func TestInitGenericWritesFiles(t *testing.T) {
	dir := t.TempDir()
	if err := doInit(initOptions{agent: "generic", dir: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agentvault/av-scrub.sh")); err != nil {
		t.Errorf("generic hook not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agentvault/AGENTVAULT.md")); err != nil {
		t.Errorf("generic doc not written: %v", err)
	}
}

// TestInitUnknownAgentErrors: an unknown agent is an error (the CLI maps this to a
// non-zero exit).
func TestInitUnknownAgentErrors(t *testing.T) {
	dir := t.TempDir()
	if err := doInit(initOptions{agent: "borg", dir: dir}); err == nil {
		t.Fatal("expected an error for an unknown agent")
	}
}

// TestInitNoClobber: a second init without --force must refuse to overwrite an existing
// file (so a user's customized hook survives).
func TestInitNoClobber(t *testing.T) {
	dir := t.TempDir()
	if err := doInit(initOptions{agent: "claude-code", dir: dir}); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(dir, ".claude/hooks/av-scrub.sh")
	custom := "#!/bin/sh\n# customized\nexec av scrub\n"
	if err := os.WriteFile(hookPath, []byte(custom), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := doInit(initOptions{agent: "claude-code", dir: dir}); err == nil {
		t.Fatal("expected refusal to overwrite without --force")
	}
	got, _ := os.ReadFile(hookPath)
	if string(got) != custom {
		t.Errorf("customized hook was overwritten:\n%s", got)
	}
	// With --force the second init succeeds.
	if err := doInit(initOptions{agent: "claude-code", dir: dir, force: true}); err != nil {
		t.Fatalf("force init failed: %v", err)
	}
}
