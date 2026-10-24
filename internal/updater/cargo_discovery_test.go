package updater

import (
	"context"
	"testing"

	"github.com/lu-zhengda/updater/internal/checker"
)

func TestDiscoverCargoCratesMarksNonRegistryCrates(t *testing.T) {
	runner := &checker.MockCmdRunner{Output: []byte(`ripgrep v14.1.0:
    rg
internal-cli v1.2.0 (https://git.example.com/acme/internal-cli#0a1b2c3d):
    internal-cli
mytool v0.1.0 (/Users/me/dev/mytool):
    mytool
`)}
	apps, err := DiscoverCargoCrates(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]struct {
		version     string
		nonRegistry bool
	}{
		"internal-cli": {"1.2.0", true},
		"mytool":       {"0.1.0", true},
		"ripgrep":      {"14.1.0", false},
	}
	if len(apps) != len(want) {
		t.Fatalf("got %d apps, want %d", len(apps), len(want))
	}
	for _, a := range apps {
		w, ok := want[a.CargoCrate]
		if !ok {
			t.Fatalf("unexpected crate %q", a.CargoCrate)
		}
		if a.Version != w.version || a.CargoNonRegistry != w.nonRegistry || a.BundleID != "cargo.crate."+a.CargoCrate {
			t.Errorf("crate %q = version %q nonRegistry %v, want %q %v", a.CargoCrate, a.Version, a.CargoNonRegistry, w.version, w.nonRegistry)
		}
	}
}
