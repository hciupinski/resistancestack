package hosthardening

import (
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestBuildAccessPlan_IncludesManagedSSHUsers(t *testing.T) {
	cfg := config.Default("demo")
	cfg.Server.SSHUser = "root"
	cfg.HostHardening.SSHHardening.AllowUsers = []string{"deployer"}

	plan := BuildAccessPlan(cfg, "203.0.113.10")
	if len(plan.ManagedAllowUsers) != 2 {
		t.Fatalf("expected guarded AllowUsers list, got %v", plan.ManagedAllowUsers)
	}
	if len(plan.FutureSSHUsers) != 1 || plan.FutureSSHUsers[0] != "deployer" {
		t.Fatalf("expected deployer as future SSH user, got %v", plan.FutureSSHUsers)
	}
	text := FormatAccessPlan(plan)
	if !strings.Contains(text, "managed AllowUsers: deployer, root") {
		t.Fatalf("expected managed AllowUsers in preview, got %q", text)
	}
	if !strings.Contains(text, "future SSH login users: deployer") {
		t.Fatalf("expected future SSH login users in preview, got %q", text)
	}
}
