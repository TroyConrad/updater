package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lu-zhengda/updater/internal/app"
	"github.com/lu-zhengda/updater/internal/checker"
	"github.com/lu-zhengda/updater/internal/installer"
)

// openRecordingRunner reports the app as running until it is asked to quit.
type openRecordingRunner struct {
	running bool
	opens   [][]string
}

func (r *openRecordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case "pgrep":
		if r.running {
			return nil, nil
		}
		return nil, errors.New("not running")
	case "osascript":
		r.running = false
	case "open":
		r.opens = append(r.opens, append([]string(nil), args...))
	}
	return nil, nil
}

func TestSecurityFailureDoesNotOpenDownloadForManualInstall(t *testing.T) {
	payload := []byte("tampered artifact")
	mux := http.NewServeMux()
	mux.HandleFunc("/Code.zip", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) })
	mux.HandleFunc("/redirect.zip", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/Code.zip", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	failures := []struct {
		name, path, digest string
	}{
		{"digest mismatch", "/Code.zip", "sha256:" + strings.Repeat("0", 64)},
		{"insecure redirect", "/redirect.zip", ""},
	}
	for _, failure := range failures {
		for _, source := range []string{"brew-info", "electron", "sparkle", "github", "vendor"} {
			for _, wasRunning := range []bool{false, true} {
				name := failure.name + "/" + source
				if wasRunning {
					name += "/running"
				}
				t.Run(name, func(t *testing.T) {
					runner := &openRecordingRunner{running: wasRunning}
					r := &checker.UpdateResult{
						App:            &app.App{Name: "Code", BundleID: "com.microsoft.VSCode", Path: t.TempDir() + "/Code.app"},
						Source:         source,
						DownloadURL:    srv.URL + failure.path,
						DownloadDigest: failure.digest,
					}
					err, rolledBack := executeUpdate(context.Background(), r, runner, nil, installer.New(runner, srv.Client()))
					if err == nil || errors.Is(err, checker.ErrOpenedExternally) {
						t.Fatalf("expected a blocking error, got %v", err)
					}
					if !installer.IsSecurityFailure(err) || !strings.Contains(err.Error(), "automatic update blocked") {
						t.Fatalf("error does not report the security block: %v", err)
					}
					if strings.Contains(err.Error(), "for manual update") {
						t.Fatalf("error claims a manual handoff: %v", err)
					}
					if rolledBack {
						t.Fatal("security rejection must not roll back the untouched app")
					}
					for _, args := range runner.opens {
						if strings.Contains(strings.Join(args, " "), r.DownloadURL) {
							t.Fatalf("rejected download was opened: %v", runner.opens)
						}
					}
					// Only an app that was running before the attempt is reopened.
					want := 0
					if wasRunning {
						want = 1
					}
					if len(runner.opens) != want || (want == 1 && strings.Join(runner.opens[0], " ") != "-a "+r.App.Path) {
						t.Fatalf("opens = %v, want %d reopen(s) of %s", runner.opens, want, r.App.Path)
					}
				})
			}
		}
	}
}

func TestTransientFailureStillOpensManualFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	runner := &openRecordingRunner{}
	r := &checker.UpdateResult{App: &app.App{Name: "Code", Path: t.TempDir() + "/Code.app"}, Source: "sparkle", DownloadURL: srv.URL + "/Code.zip"}

	err, _ := executeUpdate(context.Background(), r, runner, nil, installer.New(runner, srv.Client()))
	if err == nil || installer.IsSecurityFailure(err) || !strings.Contains(err.Error(), "for manual update") {
		t.Fatalf("expected manual handoff for a transient failure, got %v", err)
	}
	if len(runner.opens) != 1 || runner.opens[0][0] != r.DownloadURL {
		t.Fatalf("expected the download page to open, got %v", runner.opens)
	}
}
