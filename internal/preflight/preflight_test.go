package preflight

import (
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestCheckLocal_ObservabilityRequiresDataDir(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Observability.LocalDataDir = ""

	_, errs := CheckLocal(cfg, false)
	if len(errs) == 0 {
		t.Fatal("expected observability error")
	}
}

func TestCheckLocal_WarnsWhenAlertsEnabledWithoutDestinations(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Alerts.WebhookURL = ""
	cfg.Alerts.Email = ""
	cfg.Alerts.SlackURL = ""

	warnings, errs := CheckLocal(cfg, false)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %d", len(errs))
	}
	if len(warnings) == 0 {
		t.Fatal("expected alert delivery warning")
	}
}
