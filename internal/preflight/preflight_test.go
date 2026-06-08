package preflight

import (
	"os"
	"path/filepath"
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

func TestCheckLocalWithRoot_GrafanaAssetsPathMustExist(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default("demo")
	cfg.Observability.GrafanaAssetsPath = "observability/grafana"

	_, errs := CheckLocalWithRoot(cfg, root, false)
	if len(errs) == 0 {
		t.Fatal("expected grafana assets path error")
	}
}

func TestCheckLocalWithRoot_AcceptsGrafanaAssets(t *testing.T) {
	root := t.TempDir()
	dashboardPath := filepath.Join(root, "observability", "grafana", "dashboards", "business.json")
	alertingPath := filepath.Join(root, "observability", "grafana", "alerting", "payments.yaml")
	if err := os.MkdirAll(filepath.Dir(dashboardPath), 0o755); err != nil {
		t.Fatalf("mkdir dashboard dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(alertingPath), 0o755); err != nil {
		t.Fatalf("mkdir alerting dir: %v", err)
	}
	if err := os.WriteFile(dashboardPath, []byte(`{"title":"Business"}`), 0o644); err != nil {
		t.Fatalf("write dashboard: %v", err)
	}
	if err := os.WriteFile(alertingPath, []byte("apiVersion: 1\n"), 0o644); err != nil {
		t.Fatalf("write alerting: %v", err)
	}

	cfg := config.Default("demo")
	cfg.Observability.GrafanaAssetsPath = "observability/grafana"

	_, errs := CheckLocalWithRoot(cfg, root, false)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
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
