package remote

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTargetAddress(t *testing.T) {
	target := Target{Host: "example.com", User: "deployer"}
	if got := target.address(); got != "deployer@example.com" {
		t.Fatalf("address = %q", got)
	}
}

func TestTargetSSHArgs_StrictCheckingUsesKnownHosts(t *testing.T) {
	target := Target{
		Host:            "example.com",
		User:            "deployer",
		Port:            2222,
		KeyPath:         "~/.ssh/id_ed25519",
		HostKeyChecking: "strict",
		KnownHostsPath:  "~/.ssh/known_hosts",
	}

	args := target.sshArgs()
	if len(args) == 0 {
		t.Fatal("expected ssh args")
	}
	foundStrict := false
	foundKnownHosts := false
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home dir: %v", err)
	}
	wantKnownHosts := "UserKnownHostsFile=" + filepath.Join(home, ".ssh", "known_hosts")
	for i := 0; i < len(args); i++ {
		if args[i] == "StrictHostKeyChecking=yes" {
			foundStrict = true
		}
		if args[i] == wantKnownHosts {
			foundKnownHosts = true
		}
	}
	if !foundStrict {
		t.Fatal("expected strict host key checking")
	}
	if !foundKnownHosts {
		t.Fatal("expected known hosts file")
	}
}

func TestTargetSSHArgs_AcceptNew(t *testing.T) {
	target := Target{
		Host:            "example.com",
		User:            "deployer",
		Port:            22,
		KeyPath:         "~/.ssh/id_ed25519",
		HostKeyChecking: "accept-new",
	}

	args := target.sshArgs()
	found := false
	for _, arg := range args {
		if arg == "StrictHostKeyChecking=accept-new" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected accept-new host key checking")
	}
}

func TestTargetSSHArgs_UnknownModeFallsBackToStrict(t *testing.T) {
	target := Target{
		Host:            "example.com",
		User:            "deployer",
		Port:            22,
		KeyPath:         "~/.ssh/id_ed25519",
		HostKeyChecking: "invalid",
	}

	args := target.sshArgs()
	found := false
	for _, arg := range args {
		if arg == "StrictHostKeyChecking=yes" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected strict fallback")
	}
}
