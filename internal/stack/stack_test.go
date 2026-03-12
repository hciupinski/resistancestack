package stack

import (
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/deploy"
)

func TestEvaluateThresholdAlerts_ReturnsExpectedAlerts(t *testing.T) {
	cfg := config.Default("demo")
	report := StatusReport{
		SSHFail5m:    cfg.Alerts.Thresholds.SSHFail5m,
		BansPerHour:  cfg.Alerts.Thresholds.BansPerHour + 1,
		ProbePerHour: 0,
		Upstream5m:   cfg.Alerts.Thresholds.Upstream5m,
	}

	alerts := evaluateThresholdAlerts(cfg, report)
	if len(alerts) != 3 {
		t.Fatalf("expected 3 alerts, got %d", len(alerts))
	}
}

func TestPrepareRemoteReleaseScript_UsesReleasePaths(t *testing.T) {
	release := deploy.NewRelease("demo", "20260308123000")

	script := prepareRemoteReleaseScript(release)
	if !strings.Contains(script, release.RemoteReleaseDir) {
		t.Fatal("expected release directory in script")
	}
	if !strings.Contains(script, release.RemoteRoot+"/releases") {
		t.Fatal("expected releases directory in script")
	}
}
