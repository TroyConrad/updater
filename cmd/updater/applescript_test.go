package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lu-zhengda/updater/internal/app"
)

// Hostile values an installed app controls through its Info.plist
// (CFBundleDisplayName) or bundle directory name.
const appleScriptInjection = `Evil" & (do shell script "touch /tmp/pwned") & "`

var appleScriptHostileInputs = []string{
	appleScriptInjection,
	`a\" & (do shell script "id") & \"b`,
	`trailing backslash\`,
	`\\" & (do shell script "id") & "`,
	"multi\nline\" & (do shell script \"id\") & \"",
	`“smart quotes” «data utxt0041» ¬`,
	`tab	and "quotes" and \backslashes\`,
}

type recordingRunner struct {
	calls [][]string
	run   func(name string, args []string) ([]byte, error)
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if r.run != nil {
		return r.run(name, args)
	}
	return nil, nil
}

func (r *recordingRunner) osascripts() []string {
	var scripts []string
	for _, call := range r.calls {
		if call[0] == "osascript" && len(call) == 3 && call[1] == "-e" {
			scripts = append(scripts, call[2])
		}
	}
	return scripts
}

func TestQuitAppIfRunning_EscapesAppName(t *testing.T) {
	pgrepCalls := 0
	runner := &recordingRunner{run: func(name string, _ []string) ([]byte, error) {
		if name == "pgrep" {
			pgrepCalls++
			if pgrepCalls > 1 {
				return nil, errors.New("exited")
			}
		}
		return nil, nil
	}}
	a := &app.App{Name: appleScriptInjection, Path: "/Applications/Evil.app"}

	if !quitAppIfRunning(context.Background(), a, runner) {
		t.Fatal("expected the running app to be reported as quit")
	}
	scripts := runner.osascripts()
	if len(scripts) != 1 {
		t.Fatalf("expected one osascript call, got %v", runner.calls)
	}
	want := `tell application "Evil\" & (do shell script \"touch /tmp/pwned\") & \"" to quit`
	if scripts[0] != want {
		t.Fatalf("quit script = %q, want %q", scripts[0], want)
	}
}

func TestMoveToTrash_EscapesPath(t *testing.T) {
	runner := &recordingRunner{}
	a := &app.App{Name: "Evil", Path: "/Applications/" + appleScriptInjection + ".app"}

	if err := moveToTrash(context.Background(), runner, a); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	scripts := runner.osascripts()
	want := `tell application "Finder" to delete POSIX file "/Applications/Evil\" & (do shell script \"touch /tmp/pwned\") & \".app"`
	if len(scripts) != 1 || scripts[0] != want {
		t.Fatalf("trash script = %q, want %q", scripts, want)
	}
}

func TestMenubarNotificationScript_EscapesAppNames(t *testing.T) {
	got := menubarNotificationScript(appleScriptInjection+`\`, "1 update(s) available")
	want := `display notification "Evil\" & (do shell script \"touch /tmp/pwned\") & \"\\" with title "1 update(s) available"`
	if got != want {
		t.Fatalf("menubar script = %q, want %q", got, want)
	}
}

func TestSendInteractiveNotification_ShellQuotesExecutable(t *testing.T) {
	runner := &captureNotifyRunner{}
	if err := sendInteractiveNotification(context.Background(), runner, 1, appleScriptInjection); err != nil {
		t.Fatalf("sendInteractiveNotification failed: %v", err)
	}
	script := runner.args[1]
	if !strings.Contains(script, `do shell script quoted form of "`) {
		t.Errorf("executable path is not shell-quoted: %s", script)
	}
	if !strings.Contains(script, `display dialog "Evil\" & (do shell script \"touch /tmp/pwned\") & \""`) {
		t.Errorf("dialog body is not escaped: %s", script)
	}
}

// Runs the real AppleScript compiler: every escaped value must come back
// byte-for-byte as the original string, and no embedded command may run.
func TestEscapeAppleScript_RoundTripsThroughOsascript(t *testing.T) {
	if _, err := exec.LookPath("osascript"); err != nil {
		t.Skip("osascript not available")
	}
	for _, input := range appleScriptHostileInputs {
		canary := filepath.Join(t.TempDir(), "executed")
		value := strings.ReplaceAll(input, `"id"`, `"touch `+canary+`"`)
		value = strings.ReplaceAll(value, "/tmp/pwned", canary)

		out, err := exec.Command("osascript", "-e", `return "`+escapeAppleScript(value)+`"`).Output()
		if err != nil {
			t.Fatalf("osascript rejected escaped %q: %v", value, err)
		}
		if got := strings.TrimSuffix(string(out), "\n"); got != strings.ReplaceAll(value, "\n", "\r") && got != value {
			t.Errorf("round trip changed value:\n got %q\nwant %q", got, value)
		}
		if _, err := os.Stat(canary); err == nil {
			t.Fatalf("embedded command executed for input %q", value)
		}
	}
}

// Documents the original bug against the real interpreter: the unescaped
// template runs the embedded command, the escaped one does not.
func TestQuitScriptTemplate_InjectionBlockedByOsascript(t *testing.T) {
	if _, err := exec.LookPath("osascript"); err != nil {
		t.Skip("osascript not available")
	}
	canary := filepath.Join(t.TempDir(), "executed")
	name := `x" & (do shell script "touch ` + canary + `") & "`
	// `return` keeps the test from addressing any real application.
	unescaped := `return "` + name + `"`
	escaped := `return "` + escapeAppleScript(name) + `"`

	_ = exec.Command("osascript", "-e", unescaped).Run()
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("control case: unescaped template should execute the payload")
	}
	if err := os.Remove(canary); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("osascript", "-e", escaped).Run(); err != nil {
		t.Fatalf("escaped script failed: %v", err)
	}
	if _, err := os.Stat(canary); err == nil {
		t.Fatal("escaped template executed the payload")
	}
}
