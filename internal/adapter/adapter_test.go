package adapter

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// requirePerm asserts a file exists and carries the given Unix permission bits.
//
// The MODE half is skipped on Windows: Go can only ever report 0666/0444 for a file
// there ($GOROOT/src/os/types_windows.go), so 0755 is not expressible on NTFS. The
// existence half still runs — the stat is deliberately before that early return — so a
// file that was never written still fails on Windows. The production 0755 this guards is
// real and load-bearing on Unix; only the assertion is unavailable here.
func requirePerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

// TestKnownAgents: the generator registry exposes the agents the design names —
// claude-code and generic. This is the SSOT for "which agents can av init target".
func TestKnownAgents(t *testing.T) {
	agents := KnownAgents()
	for _, want := range []string{"claude-code", "generic"} {
		found := false
		for _, a := range agents {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("KnownAgents() = %v, missing %q", agents, want)
		}
	}
}

// TestUnknownAgentErrors: an unrecognized agent name is a clear error (so the CLI can
// map it to a non-zero exit). The error must name the unknown agent and list the known
// ones so the user can correct it.
func TestUnknownAgentErrors(t *testing.T) {
	_, err := Files("does-not-exist")
	if err == nil {
		t.Fatal("expected an error for an unknown agent")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error %q should name the unknown agent", err)
	}
	if !strings.Contains(err.Error(), "claude-code") {
		t.Errorf("error %q should list the known agents", err)
	}
}

// fileByPath finds a generated file by its relative path in the set.
func fileByPath(files []File, path string) (File, bool) {
	for _, f := range files {
		if f.Path == path {
			return f, true
		}
	}
	return File{}, false
}

// TestClaudeCodeHookScript: the claude-code adapter generates a hook script that is a
// shell script (starts with #!), is executable (0755), and pipes its stdin through
// `av scrub` (the layer-2 redaction the design requires for context-ingress channels).
func TestClaudeCodeHookScript(t *testing.T) {
	files, err := Files("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	hook, ok := fileByPath(files, ".claude/hooks/av-scrub.sh")
	if !ok {
		t.Fatalf("claude-code set missing the hook script; got %v", paths(files))
	}
	if !strings.HasPrefix(hook.Content, "#!") {
		t.Errorf("hook script must start with a shebang, got %q", firstLine(hook.Content))
	}
	if !strings.Contains(hook.Content, "av scrub") {
		t.Errorf("hook script must pipe stdin through `av scrub`, got:\n%s", hook.Content)
	}
	if hook.Mode != 0o755 {
		t.Errorf("hook script mode = %o, want 0755 (executable)", hook.Mode)
	}
}

// TestClaudeCodeSkillDoc: the skill/doc tells the agent the three rules from the design:
// use `av run` to run commands with secrets it never sees, pipe tool output through
// `av scrub`, and treat `{{AV:NAME}}` as an opaque reference (never recover the value).
// It must also carry the scrub-coverage contract (the channels that MUST be hooked).
func TestClaudeCodeSkillDoc(t *testing.T) {
	files, err := Files("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	skill, ok := fileByPath(files, ".claude/skills/agentvault/SKILL.md")
	if !ok {
		t.Fatalf("claude-code set missing the skill doc; got %v", paths(files))
	}
	for _, want := range []string{"av run", "av scrub", "{{AV:NAME}}", "opaque", "av read"} {
		if !strings.Contains(skill.Content, want) {
			t.Errorf("skill doc must mention %q", want)
		}
	}
	// Exact-syntax quick reference (subagent tests showed agents otherwise guess the
	// surface wrong — no --profile, invented profile names): the doc must teach the
	// precise invocation, that names live in agentvault.yaml, and the config-file
	// ${VAR}+av-run pattern (so a secret a tool reads from a file is never written to disk).
	for _, want := range []string{"av run --profile", "agentvault.yaml", "${NPM_TOKEN}"} {
		if !strings.Contains(skill.Content, want) {
			t.Errorf("skill doc must teach exact usage %q", want)
		}
	}
	// The scrub-coverage contract: the doc enumerates the context-ingress channels
	// that MUST be hooked (so a human wiring it knows the requirement).
	for _, channel := range []string{"Bash", "file read", "MCP"} {
		if !strings.Contains(skill.Content, channel) {
			t.Errorf("skill doc must enumerate the %q context-ingress channel (scrub-coverage contract)", channel)
		}
	}
}

// TestClaudeCodeHooksSnippet: a settings/hooks snippet is generated documenting the
// PostToolUse wiring. The EXACT Claude Code schema varies by version, so it is a
// template to MERGE (not presented as authoritative) — the test asserts it references
// the scrub hook + PostToolUse and is flagged as a merge template, not exact bytes.
func TestClaudeCodeHooksSnippet(t *testing.T) {
	files, err := Files("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	snippet, ok := fileByPath(files, ".claude/agentvault.hooks.json")
	if !ok {
		t.Fatalf("claude-code set missing the hooks snippet; got %v", paths(files))
	}
	for _, want := range []string{"PostToolUse", "av-scrub.sh"} {
		if !strings.Contains(snippet.Content, want) {
			t.Errorf("hooks snippet must reference %q", want)
		}
	}
}

// TestGenericVariant: the generic agent generates a minimal hook script + a doc with the
// same contract, without Claude-Code specifics (no .claude/ paths).
func TestGenericVariant(t *testing.T) {
	files, err := Files("generic")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("generic set is empty")
	}
	var hook, doc bool
	for _, f := range files {
		if strings.HasPrefix(f.Path, ".claude/") {
			t.Errorf("generic variant must not use Claude-Code paths, got %q", f.Path)
		}
		if strings.HasSuffix(f.Path, ".sh") {
			hook = true
			if !strings.HasPrefix(f.Content, "#!") || !strings.Contains(f.Content, "av scrub") {
				t.Errorf("generic hook must be a shell script piping `av scrub`, got:\n%s", f.Content)
			}
			if f.Mode != 0o755 {
				t.Errorf("generic hook mode = %o, want 0755", f.Mode)
			}
		}
		if strings.HasSuffix(f.Path, ".md") {
			doc = true
			for _, want := range []string{"av run", "av scrub", "{{AV:NAME}}"} {
				if !strings.Contains(f.Content, want) {
					t.Errorf("generic doc must mention %q", want)
				}
			}
		}
	}
	if !hook {
		t.Error("generic set missing a hook script")
	}
	if !doc {
		t.Error("generic set missing a doc")
	}
}

// TestAdapterExportsNoPrompt: every generated agent's hook script must export
// AV_NO_PROMPT=1 so the AGENT path returns the clean exit-69 pause (a human unlocks)
// instead of blocking the agent on an on-demand Touch ID. The hook is the shell entry
// point that runs `av scrub`, and it also fronts the agent's `av run` calls' environment.
func TestAdapterExportsNoPrompt(t *testing.T) {
	for _, agent := range KnownAgents() {
		files, err := Files(agent)
		if err != nil {
			t.Fatalf("Files(%q): %v", agent, err)
		}
		var sawHook bool
		for _, f := range files {
			if !strings.HasSuffix(f.Path, ".sh") {
				continue
			}
			sawHook = true
			if !strings.Contains(f.Content, "AV_NO_PROMPT=1") {
				t.Errorf("%s hook %s must export AV_NO_PROMPT=1, got:\n%s", agent, f.Path, f.Content)
			}
		}
		if !sawHook {
			t.Errorf("%s set has no hook script to carry AV_NO_PROMPT", agent)
		}
	}
}

// TestWriteCreatesFiles: Write materializes every file under dir at its relative path,
// with the declared mode for the hook script, and the parent dirs are created.
func TestWriteCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	files, _ := Files("claude-code")
	if err := Write(dir, files, false); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		p := filepath.Join(dir, f.Path)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist: %v", f.Path, err)
		}
		if f.Mode == 0o755 {
			requirePerm(t, p, 0o755)
		}
	}
}

// TestWriteNoClobber: Write refuses to overwrite an existing file without force, so a
// user's customized hook is never destroyed. The pre-existing content must survive and
// an error must be returned naming the file.
func TestWriteNoClobber(t *testing.T) {
	dir := t.TempDir()
	files, _ := Files("claude-code")
	hookPath := filepath.Join(dir, ".claude/hooks/av-scrub.sh")
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		t.Fatal(err)
	}
	const custom = "#!/bin/sh\n# my customized hook\nexec av scrub\n"
	if err := os.WriteFile(hookPath, []byte(custom), 0o755); err != nil {
		t.Fatal(err)
	}

	err := Write(dir, files, false)
	if err == nil {
		t.Fatal("expected Write to refuse clobbering an existing file without force")
	}
	if !strings.Contains(err.Error(), "av-scrub.sh") {
		t.Errorf("error %q should name the conflicting file", err)
	}
	got, _ := os.ReadFile(hookPath)
	if string(got) != custom {
		t.Errorf("existing file was modified; got:\n%s", got)
	}
}

// TestWriteForceOverwrites: with force, Write replaces an existing file.
func TestWriteForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	files, _ := Files("claude-code")
	hookPath := filepath.Join(dir, ".claude/hooks/av-scrub.sh")
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte("# old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, files, true); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(hookPath)
	if !strings.Contains(string(got), "av scrub") {
		t.Errorf("force did not overwrite the file; got:\n%s", got)
	}
}

func paths(files []File) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Path
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
