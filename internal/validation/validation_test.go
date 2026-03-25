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

func TestCheck_InvalidOperatorAccessModeReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.HostHardening.UFWPolicy.OperatorAccessMode = "invalid"

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}

func TestCheck_PublicHardenedWithoutAllowlistWarns(t *testing.T) {
	cfg := config.Default("proj")
	cfg.HostHardening.UFWPolicy.AdminAllowlist = nil
	cfg.HostHardening.UFWPolicy.OperatorAccessMode = config.OperatorAccessModePublicHardened

	warnings, errs := Check(cfg)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %d", len(errs))
	}
	found := false
	for _, warning := range warnings {
		if warning == "host_hardening.ufw_policy.admin_allowlist is empty; public_hardened mode will keep SSH reachable on server.ssh_port" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected public_hardened allowlist warning")
	}
}

func TestCheck_InvalidSARIFUploadModeReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.CI.GitHub.SARIFUploadMode = "sometimes"

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}

func TestCheck_InvalidRepositoryVisibilityReturnsError(t *testing.T) {
	cfg := config.Default("proj")
	cfg.CI.GitHub.RepositoryVisibility = "partner"

	_, errs := Check(cfg)
	if len(errs) == 0 {
		t.Fatal("expected validation errors")
	}
}

func TestCheck_EnabledSARIFWithoutSupportedRepoWarns(t *testing.T) {
	cfg := config.Default("proj")
	cfg.CI.GitHub.RepositoryVisibility = config.RepoVisibilityPrivate
	cfg.CI.GitHub.CodeScanningEnabled = false
	cfg.CI.GitHub.SARIFUploadMode = config.CISARIFUploadModeEnabled

	warnings, errs := Check(cfg)
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %d", len(errs))
	}
	found := false
	for _, warning := range warnings {
		if warning == "ci.github.sarif_upload_mode=enabled but repository_visibility is not public and code_scanning_enabled=false; SARIF upload may fail in GitHub Actions" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected SARIF support warning")
	}
}
