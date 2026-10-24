package main

import (
	"context"
	"strings"
	"testing"

	"github.com/lu-zhengda/updater/internal/app"
	"github.com/lu-zhengda/updater/internal/checker"
)

func TestExecuteUpdateRefusesNonRegistryCargoCrate(t *testing.T) {
	runner := &recordingCargoRunner{}
	r := &checker.UpdateResult{
		App:           &app.App{Name: "internal-cli", Source: app.SourceCargo, CargoCrate: "internal-cli", CargoNonRegistry: true},
		Source:        "cargo",
		HasUpdate:     true,
		LatestVersion: "99.0.0",
	}
	err, _ := executeUpdate(context.Background(), r, runner, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not installed from crates.io") {
		t.Fatalf("expected refusal, got %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("no command may run for a non-registry crate, got %v", runner.calls)
	}
}

func TestExecuteUpdateStillUpgradesRegistryCargoCrate(t *testing.T) {
	runner := &recordingCargoRunner{}
	r := &checker.UpdateResult{
		App:    &app.App{Name: "ripgrep", Source: app.SourceCargo, CargoCrate: "ripgrep"},
		Source: "cargo",
	}
	if err, _ := executeUpdate(context.Background(), r, runner, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runner.calls) != 1 || runner.calls[0] != "cargo install ripgrep" {
		t.Fatalf("calls = %v, want [cargo install ripgrep]", runner.calls)
	}
}

type recordingCargoRunner struct{ calls []string }

func (r *recordingCargoRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return nil, nil
}
