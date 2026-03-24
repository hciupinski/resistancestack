package validation

import (
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestCheck_DefaultConfigIsValid(t *testing.T) {
	cfg := config.Default("proj")

	_, errs := Check(cfg)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %d", len(errs))
	}
}

func TestCheck_InvalidModeReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.Mode.Strategy = "managed_deploy"

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}

func TestCheck_InvalidCIProviderReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.CI.Provider = "gitlab"

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}

func TestCheck_InvalidAllowlistReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.HostHardening.UFWPolicy.AdminAllowlist = []string{"not-a-cidr"}

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}

func TestCheck_InvalidHealthcheckURLReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.AppInventory.HealthcheckURLs = []string{"notaurl"}

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}
