package observability

import (
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestBuildEnableScript_DefaultContent(t *testing.T) {
	cfg := config.Default("demo")
	got := BuildEnableScript(cfg)

	required := []string{
		"resistack-grafana.service",
		"resistack-loki.service",
		"resistack-alloy.service",
		"resistack-observability-snapshot.timer",
		"Grafana",
		"Loki",
		`STAGING_DIR="$(mktemp -d /tmp/resistack-observability.`,
		`${GRAFANA_PROVISIONING}/datasources`,
		`${GRAFANA_PROVISIONING}/dashboards`,
		`OnUnitActiveSec=60s`,
		`http://${PANEL_HOST}:${PANEL_PORT}/`,
		"resistack-live-logs",
		`loki.source.journal "systemd"`,
	}
	for _, fragment := range required {
		if !strings.Contains(got, fragment) {
			t.Fatalf("expected enable script to contain %q", fragment)
		}
	}
	if strings.Contains(got, "PAGE_CONTENT=") {
		t.Fatal("expected enable script to avoid passing HTML through PAGE_CONTENT env var")
	}
}

func TestBuildDisableScript_DefaultContent(t *testing.T) {
	cfg := config.Default("demo")
	got := BuildDisableScript(cfg)

	required := []string{
		"resistack-grafana.service",
		"resistack-loki.service",
		"resistack-alloy.service",
		"resistack-observability-snapshot.timer",
		"resistack-observability-ui.service",
		cfg.Observability.LocalDataDir,
	}
	for _, fragment := range required {
		if !strings.Contains(got, fragment) {
			t.Fatalf("expected disable script to contain %q", fragment)
		}
	}
}

func TestSplitBind_DefaultsAndIPv6(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort string
	}{
		{name: "empty", input: "", wantHost: "127.0.0.1", wantPort: "9400"},
		{name: "port only", input: ":9500", wantHost: "127.0.0.1", wantPort: "9500"},
		{name: "ipv4", input: "127.0.0.1:9600", wantHost: "127.0.0.1", wantPort: "9600"},
		{name: "ipv6", input: "::1:9700", wantHost: "::1", wantPort: "9700"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotPort := splitBind(tt.input)
			if gotHost != tt.wantHost || gotPort != tt.wantPort {
				t.Fatalf("splitBind(%q) = (%q, %q), want (%q, %q)", tt.input, gotHost, gotPort, tt.wantHost, tt.wantPort)
			}
		})
	}
}
