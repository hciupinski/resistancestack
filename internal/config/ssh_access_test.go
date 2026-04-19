package config

import (
	"reflect"
	"testing"
)

func TestManagedSSHAllowUsers_AppendsOperatorWhenGuardEnabled(t *testing.T) {
	cfg := Default("demo")
	cfg.Server.SSHUser = "root"
	cfg.HostHardening.SSHHardening.AllowUsers = []string{"deployer"}

	got := ManagedSSHAllowUsers(cfg)
	want := []string{"deployer", "root"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ManagedSSHAllowUsers() = %v, want %v", got, want)
	}
}

func TestManagedSSHAllowUsers_DoesNotInventAllowUsers(t *testing.T) {
	cfg := Default("demo")
	cfg.Server.SSHUser = "root"
	cfg.HostHardening.SSHHardening.AllowUsers = nil

	if got := ManagedSSHAllowUsers(cfg); got != nil {
		t.Fatalf("ManagedSSHAllowUsers() = %v, want nil", got)
	}
}

func TestFutureSSHLoginUsers_ExcludesRootWhenDisabled(t *testing.T) {
	cfg := Default("demo")
	cfg.Server.SSHUser = "root"
	cfg.HostHardening.SSHHardening.AllowUsers = []string{"deployer"}

	got := FutureSSHLoginUsers(cfg)
	want := []string{"deployer"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FutureSSHLoginUsers() = %v, want %v", got, want)
	}
}

func TestFutureSSHLoginUsers_UsesConfiguredSSHUserWithoutAllowUsers(t *testing.T) {
	cfg := Default("demo")
	cfg.Server.SSHUser = "deployer"
	cfg.HostHardening.SSHHardening.AllowUsers = nil

	got := FutureSSHLoginUsers(cfg)
	want := []string{"deployer"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FutureSSHLoginUsers() = %v, want %v", got, want)
	}
}

func TestPreferredDeployUser_PrefersNonRootFutureUser(t *testing.T) {
	cfg := Default("demo")
	cfg.Server.SSHUser = "root"
	cfg.HostHardening.SSHHardening.AllowUsers = []string{"deployer"}

	if got := PreferredDeployUser(cfg); got != "deployer" {
		t.Fatalf("PreferredDeployUser() = %q, want deployer", got)
	}
}
