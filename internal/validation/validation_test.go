package validation

import (
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestCheck_DefaultConfigIsValid(t *testing.T) {
	cfg := config.Default("proj")

	warnings, errs := Check(cfg)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %d", len(errs))
	}
	if len(warnings) == 0 {
		t.Fatal("expected default warnings for placeholder dashboard secret")
	}
}

func TestCheck_InvalidProfileReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.Security.Profile = "invalid"

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}

func TestCheck_MissingUpstreamReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.App.UpstreamURL = ""

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}

func TestCheck_TLSEnabledWithoutEmailReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.TLS.Enabled = true
	cfg.TLS.Email = ""

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}

func TestCheck_TLSStagingAddsWarning(t *testing.T) {
	cfg := config.Default("proj")
	cfg.TLS.Enabled = true
	cfg.TLS.Staging = true

	warnings, errs := Check(cfg)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %d", len(errs))
	}
	if len(warnings) < 2 {
		t.Fatal("expected tls staging warning")
	}
}

func TestCheck_InvalidAllowlistReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.Security.AdminAllowlist = []string{"not-a-cidr"}

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}
