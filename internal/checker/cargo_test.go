package checker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lu-zhengda/updater/internal/app"
)

func TestCargoChecker_Name(t *testing.T) {
	c := NewCargoChecker(nil, "")
	if got := c.Name(); got != "cargo" {
		t.Errorf("Name() = %q, want %q", got, "cargo")
	}
}

func TestCargoChecker_CanCheck(t *testing.T) {
	c := NewCargoChecker(nil, "")

	tests := []struct {
		name string
		app  *app.App
		want bool
	}{
		{
			name: "cargo crate",
			app:  &app.App{Source: app.SourceCargo, CargoCrate: "ripgrep"},
			want: true,
		},
		{
			name: "cargo source without crate name",
			app:  &app.App{Source: app.SourceCargo},
			want: false,
		},
		{
			name: "uv tool",
			app:  &app.App{Source: app.SourceUv, UvTool: "ruff"},
			want: false,
		},
		{
			name: "unknown source with cargo crate name set",
			app:  &app.App{Source: app.SourceUnknown, CargoCrate: "ripgrep"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.CanCheck(tt.app); got != tt.want {
				t.Errorf("CanCheck() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCargoChecker_Check(t *testing.T) {
	tests := []struct {
		name       string
		app        *app.App
		body       string
		status     int
		wantUpdate bool
		wantLatest string
		wantErr    bool
	}{
		{
			name:       "outdated crate",
			app:        &app.App{Name: "ripgrep", Version: "13.0.0", Source: app.SourceCargo, CargoCrate: "ripgrep"},
			body:       `{"crate":{"max_stable_version":"14.1.0","newest_version":"14.1.0"}}`,
			status:     200,
			wantUpdate: true,
			wantLatest: "14.1.0",
		},
		{
			name:       "up-to-date crate",
			app:        &app.App{Name: "bat", Version: "0.24.0", Source: app.SourceCargo, CargoCrate: "bat"},
			body:       `{"crate":{"max_stable_version":"0.24.0","newest_version":"0.24.0"}}`,
			status:     200,
			wantUpdate: false,
			wantLatest: "0.24.0",
		},
		{
			name:       "falls back to newest_version when no stable release",
			app:        &app.App{Name: "preview", Version: "0.1.0", Source: app.SourceCargo, CargoCrate: "preview"},
			body:       `{"crate":{"max_stable_version":"","newest_version":"0.2.0-beta.1"}}`,
			status:     200,
			wantUpdate: true,
			wantLatest: "0.2.0-beta.1",
		},
		{
			name:    "missing crate name",
			app:     &app.App{Name: "mystery", Source: app.SourceCargo},
			wantErr: true,
		},
		{
			name:    "crates.io returns 404",
			app:     &app.App{Name: "ghost", Version: "1.0.0", Source: app.SourceCargo, CargoCrate: "ghost"},
			status:  404,
			wantErr: true,
		},
		{
			name:    "crates.io returns invalid JSON",
			app:     &app.App{Name: "ripgrep", Version: "13.0.0", Source: app.SourceCargo, CargoCrate: "ripgrep"},
			body:    `not json`,
			status:  200,
			wantErr: true,
		},
		{
			name:    "crates.io returns empty versions",
			app:     &app.App{Name: "ripgrep", Version: "13.0.0", Source: app.SourceCargo, CargoCrate: "ripgrep"},
			body:    `{"crate":{"max_stable_version":"","newest_version":""}}`,
			status:  200,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
				}
				fmt.Fprint(w, tt.body)
			}))
			defer ts.Close()

			c := NewCargoChecker(ts.Client(), ts.URL)
			result, err := c.Check(context.Background(), tt.app)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.HasUpdate != tt.wantUpdate {
				t.Errorf("HasUpdate = %v, want %v", result.HasUpdate, tt.wantUpdate)
			}
			if result.LatestVersion != tt.wantLatest {
				t.Errorf("LatestVersion = %q, want %q", result.LatestVersion, tt.wantLatest)
			}
			if result.Source != "cargo" {
				t.Errorf("Source = %q, want %q", result.Source, "cargo")
			}
		})
	}
}

func TestCargoChecker_Check_SendsUserAgent(t *testing.T) {
	var gotUA string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		fmt.Fprint(w, `{"crate":{"max_stable_version":"1.0.0"}}`)
	}))
	defer ts.Close()

	c := NewCargoChecker(ts.Client(), ts.URL)
	a := &app.App{Name: "ripgrep", Version: "0.9.0", Source: app.SourceCargo, CargoCrate: "ripgrep"}
	if _, err := c.Check(context.Background(), a); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotUA == "" {
		t.Error("User-Agent header was empty; crates.io rejects requests without one")
	}
}

func TestCargoChecker_Check_CachesResults(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		fmt.Fprint(w, `{"crate":{"max_stable_version":"1.2.3"}}`)
	}))
	defer ts.Close()

	c := NewCargoChecker(ts.Client(), ts.URL)
	a := &app.App{Name: "ripgrep", Version: "1.0.0", Source: app.SourceCargo, CargoCrate: "ripgrep"}

	for i := 0; i < 3; i++ {
		if _, err := c.Check(context.Background(), a); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("crates.io hits = %d, want 1 (results should be cached)", calls)
	}
}

func TestListInstalledCargoCrates(t *testing.T) {
	tests := []struct {
		name    string
		output  []byte
		err     error
		want    map[string]CargoCrateInfo
		wantErr bool
	}{
		{
			name: "normal output",
			output: []byte(`bat v0.24.0:
    bat
cargo-edit v0.12.2:
    cargo-add
    cargo-rm
    cargo-set-version
    cargo-upgrade
ripgrep v14.1.0:
    rg
`),
			want: map[string]CargoCrateInfo{
				"bat":        {Version: "0.24.0"},
				"cargo-edit": {Version: "0.12.2"},
				"ripgrep":    {Version: "14.1.0"},
			},
		},
		{
			name:   "no crates installed",
			output: []byte(""),
			want:   map[string]CargoCrateInfo{},
		},
		{
			name: "crate installed from local path",
			output: []byte(`mytool v0.1.0 (/Users/me/dev/mytool):
    mytool
`),
			want: map[string]CargoCrateInfo{"mytool": {Version: "0.1.0", NonRegistry: true}},
		},
		{
			name: "crate installed from git",
			output: []byte(`gitcrate v2.0.0 (https://github.com/owner/repo#abcdef):
    gitcrate
`),
			want: map[string]CargoCrateInfo{"gitcrate": {Version: "2.0.0", NonRegistry: true}},
		},
		{
			name: "crate name containing v",
			output: []byte(`cargo-nextest v0.9.72:
    cargo-nextest
`),
			want: map[string]CargoCrateInfo{"cargo-nextest": {Version: "0.9.72"}},
		},
		{
			name: "mixed registry and non-registry crates",
			output: []byte(`ripgrep v14.1.0:
    rg
internal-cli v1.2.0 (https://git.example.com/acme/internal-cli#0a1b2c3d):
    internal-cli
private-tool v0.3.0 (registry ` + "`acme`" + `):
    private-tool
`),
			want: map[string]CargoCrateInfo{
				"ripgrep":      {Version: "14.1.0"},
				"internal-cli": {Version: "1.2.0", NonRegistry: true},
				"private-tool": {Version: "0.3.0", NonRegistry: true},
			},
		},
		{
			name:    "cargo command fails",
			err:     fmt.Errorf("cargo not found"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &MockCmdRunner{Output: tt.output, Err: tt.err}
			got, err := ListInstalledCargoCrates(context.Background(), runner)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d crates (%v), want %d (%v)", len(got), got, len(tt.want), tt.want)
			}
			for name, want := range tt.want {
				if gotInfo, ok := got[name]; !ok {
					t.Errorf("missing crate %q", name)
				} else if gotInfo != want {
					t.Errorf("crate %q = %+v, want %+v", name, gotInfo, want)
				}
			}
		})
	}
}

func TestParseCargoInstallLine(t *testing.T) {
	tests := []struct {
		line            string
		wantName        string
		wantVer         string
		wantNonRegistry bool
		wantOK          bool
	}{
		{"ripgrep v14.1.0:", "ripgrep", "14.1.0", false, true},
		{"cargo-edit v0.12.2:", "cargo-edit", "0.12.2", false, true},
		{"cargo-nextest v0.9.72:", "cargo-nextest", "0.9.72", false, true},
		{"mytool v0.1.0 (/Users/me/dev/mytool):", "mytool", "0.1.0", true, true},
		{"gitcrate v2.0.0 (https://github.com/owner/repo#abc):", "gitcrate", "2.0.0", true, true},
		{"private-tool v0.3.0 (registry `acme`):", "private-tool", "0.3.0", true, true},
		{"mytool v0.1.0 (/Users/me/dev/my v2 tool):", "mytool", "0.1.0", true, true}, // " v" inside a path
		{"    rg", "", "", false, false},                                             // binary line, no colon
		{"ripgrep v14.1.0", "", "", false, false},                                    // missing trailing colon
		{"no-version-here:", "", "", false, false},
		{"", "", "", false, false},
		{"weird vNotAVersion:", "", "", false, false},
		{"weird 14.1.0:", "", "", false, false}, // version without v prefix
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			name, info, ok := parseCargoInstallLine(tt.line)
			if ok != tt.wantOK || name != tt.wantName || info.Version != tt.wantVer || info.NonRegistry != tt.wantNonRegistry {
				t.Errorf("parseCargoInstallLine(%q) = (%q, %+v, %v), want (%q, %q, nonRegistry=%v, %v)",
					tt.line, name, info, ok, tt.wantName, tt.wantVer, tt.wantNonRegistry, tt.wantOK)
			}
		})
	}
}

func TestCargoCheckSkipsNonRegistryCrateWithoutQueryingCratesIO(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("crates.io must not be queried for a non-registry crate: %s", r.URL.Path)
		_, _ = w.Write([]byte(`{"crate":{"max_stable_version":"99.0.0","newest_version":"99.0.0"}}`))
	}))
	defer srv.Close()

	c := NewCargoChecker(srv.Client(), srv.URL)
	a := &app.App{Name: "internal-cli", Version: "1.2.0", Source: app.SourceCargo, CargoCrate: "internal-cli", CargoNonRegistry: true}
	result, err := c.Check(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasUpdate || result.LatestVersion != "1.2.0" || result.IsMajorUpdate {
		t.Fatalf("non-registry crate reported an update: %+v", result)
	}
}

func TestCargoCheckStillQueriesRegistryCrates(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"crate":{"max_stable_version":"15.0.0","newest_version":"15.0.0"}}`))
	}))
	defer srv.Close()

	c := NewCargoChecker(srv.Client(), srv.URL)
	a := &app.App{Name: "ripgrep", Version: "14.1.0", Source: app.SourceCargo, CargoCrate: "ripgrep"}
	result, err := c.Check(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hits != 1 || !result.HasUpdate || result.LatestVersion != "15.0.0" {
		t.Fatalf("registry crate check = %+v (hits %d)", result, hits)
	}
}
