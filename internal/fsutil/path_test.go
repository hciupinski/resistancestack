package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandHome_Tilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("user home dir: %v", err)
	}

	got := ExpandHome("~/keys/id_ed25519")
	want := filepath.Join(home, "keys", "id_ed25519")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
