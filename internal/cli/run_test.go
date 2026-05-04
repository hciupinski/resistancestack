package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_PrintsUsageWhenNoArgs(t *testing.T) {
	var out bytes.Buffer

	if err := Run(nil, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if got := out.String(); !strings.Contains(got, "ResistanceStack v2 CLI") || !strings.Contains(got, "Available Commands:") {
		t.Fatalf("expected usage output, got %q", got)
	}
}

func TestRun_PrintsUsageForHelpAliases(t *testing.T) {
	aliases := [][]string{{"help"}, {"-h"}, {"--help"}}

	for _, args := range aliases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out bytes.Buffer
			if err := Run(args, &out, &bytes.Buffer{}); err != nil {
				t.Fatalf("run %v: %v", args, err)
			}
			if got := out.String(); !strings.Contains(got, "Commands:") {
				t.Fatalf("expected command list, got %q", got)
			}
		})
	}
}

func TestRun_ReturnsUnknownCommandError(t *testing.T) {
	err := Run([]string{"unknown"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected unknown command error")
	}
	if got := err.Error(); !strings.Contains(got, `unknown command "unknown"`) {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestRun_CIRequiresSubcommand(t *testing.T) {
	err := Run([]string{"ci"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected missing ci subcommand error")
	}
	if got := err.Error(); got != "ci requires a subcommand: generate or validate" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestRun_ObservabilityRequiresSubcommand(t *testing.T) {
	err := Run([]string{"observability"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected missing observability subcommand error")
	}
	if got := err.Error(); got != "observability requires a subcommand: enable or disable" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestRun_DeployUserRequiresSubcommand(t *testing.T) {
	err := Run([]string{"deploy-user"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected missing deploy-user subcommand error")
	}
	if got := err.Error(); got != "deploy-user requires a subcommand: check or bootstrap" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestRun_RootHelpShowsPersistentFlagsAndCompletion(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"--help"}, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("run help: %v", err)
	}
	got := out.String()
	for _, want := range []string{"--config", "--env", "--output", "--verbose", "--non-interactive", "completion"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected help to contain %q, got %q", want, got)
		}
	}
}

func TestRun_CommandHelpShowsPersistentFlags(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"audit", "--help"}, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("run audit help: %v", err)
	}
	got := out.String()
	for _, want := range []string{"--dry-run", "--config", "--env", "--output"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected audit help to contain %q, got %q", want, got)
		}
	}
}

func TestExitCode_MapsNotImplementedToUsageError(t *testing.T) {
	err := Run([]string{"doctor"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected doctor to be not implemented")
	}
	if got := ExitCode(err); got != 2 {
		t.Fatalf("unexpected exit code %d", got)
	}
}
