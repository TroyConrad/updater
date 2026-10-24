package installer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lu-zhengda/updater/internal/checker"
)

// commandRunner answers by command name so temp-dir paths need not be known.
type commandRunner struct {
	responses map[string]checker.MockResponse
}

func (r *commandRunner) Run(_ context.Context, name string, _ ...string) ([]byte, error) {
	resp := r.responses[name]
	return resp.Output, resp.Err
}

func TestDownloadSecurityRejectionsAreSecurityFailures(t *testing.T) {
	payload := []byte("payload")
	mux := http.NewServeMux()
	mux.HandleFunc("/ok.zip", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) })
	mux.HandleFunc("/insecure-redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/update.dmg", http.StatusFound)
	})
	mux.HandleFunc("/traversal", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="../../evil.dmg"`)
		_, _ = w.Write(payload)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	tests := []struct {
		name, url, digest string
	}{
		{"plain http URL", "http://example.com/update.dmg", ""},
		{"insecure redirect", ts.URL + "/insecure-redirect", ""},
		{"unsafe filename", ts.URL + "/traversal", ""},
		{"digest mismatch", ts.URL + "/ok.zip", "sha256:" + strings.Repeat("0", 64)},
		{"unsupported digest", ts.URL + "/ok.zip", "md5:abc"},
		{"malformed digest", ts.URL + "/ok.zip", "nodigest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := New(&checker.MockCmdRunner{}, ts.Client())
			_, err := inst.download(context.Background(), tt.url, t.TempDir(), tt.digest)
			if err == nil {
				t.Fatal("expected download to be rejected")
			}
			if !IsSecurityFailure(err) {
				t.Fatalf("expected security failure, got %v", err)
			}
			if MayRequireRollback(err) {
				t.Fatal("security rejection must not request rollback")
			}
		})
	}
}

func TestTransientDownloadFailuresAreNotSecurityFailures(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	inst := New(&checker.MockCmdRunner{}, ts.Client())
	_, err := inst.download(context.Background(), ts.URL+"/app.zip", t.TempDir(), "")
	if err == nil || IsSecurityFailure(err) {
		t.Fatalf("503 must be a non-security failure, got %v", err)
	}

	closedURL := ts.URL
	ts.Close()
	_, err = inst.download(context.Background(), closedURL+"/app.zip", t.TempDir(), "")
	if err == nil || IsSecurityFailure(err) {
		t.Fatalf("connection failure must be a non-security failure, got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = inst.download(ctx, "https://example.com/app.zip", t.TempDir(), "")
	if err == nil || IsSecurityFailure(err) {
		t.Fatalf("cancellation must be a non-security failure, got %v", err)
	}
}

func TestVerifierRejectionsAreSecurityFailures(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact")
	if err := os.WriteFile(artifact, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &commandRunner{responses: map[string]checker.MockResponse{
		"hdiutil": {Output: []byte("/Volumes/TestApp\n")},
		"ls":      {Output: []byte("TestApp.app\n")},
	}}
	inst := New(runner, nil)
	inst.verifier = rejectVerifier{}

	installs := map[string]func() error{
		"dmg": func() error {
			return inst.installDMG(context.Background(), artifact, "/Applications/TestApp.app", "TestApp")
		},
		"zip": func() error {
			return inst.installZIP(context.Background(), artifact, "/Applications/TestApp.app", "TestApp")
		},
		"pkg": func() error { return inst.installPKG(context.Background(), artifact, "/Applications/TestApp.app") },
	}
	for name, install := range installs {
		t.Run(name, func(t *testing.T) {
			err := install()
			if err == nil || !strings.Contains(err.Error(), "security verification") {
				t.Fatalf("expected verification error, got %v", err)
			}
			if !IsSecurityFailure(err) {
				t.Fatalf("verification rejection must be a security failure: %v", err)
			}
			if MayRequireRollback(err) {
				t.Fatal("verification rejection must not request rollback")
			}
		})
	}
}

func TestNonSecurityInstallFailuresAreNotSecurityFailures(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(artifact, []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	failing := &commandRunner{responses: map[string]checker.MockResponse{
		"hdiutil": {Err: errors.New("attach failed")},
		"ditto":   {Err: errors.New("extract failed")},
		"sudo":    {Err: errors.New("installer failed")},
	}}
	inst := New(failing, nil)
	inst.verifier = allowVerifier{}

	for name, err := range map[string]error{
		"dmg mount":   inst.installDMG(context.Background(), artifact, "/Applications/TestApp.app", "TestApp"),
		"zip extract": inst.installZIP(context.Background(), artifact, "/Applications/TestApp.app", "TestApp"),
		"pkg install": inst.installPKG(context.Background(), artifact, "/Applications/TestApp.app"),
	} {
		if err == nil || IsSecurityFailure(err) {
			t.Errorf("%s: expected non-security failure, got %v", name, err)
		}
	}
	if IsSecurityFailure(fmt.Errorf("wrapped: %w", errors.New("plain"))) || IsSecurityFailure(nil) {
		t.Fatal("plain errors must not be security failures")
	}
	if !IsSecurityFailure(fmt.Errorf("context: %w", &securityError{errors.New("x")})) {
		t.Fatal("wrapped security failures must still be detected")
	}
}
