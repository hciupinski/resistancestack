package version

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCurrentReturnsFallback(t *testing.T) {
	old := Version
	t.Cleanup(func() {
		Version = old
	})

	Version = ""

	if got := Current(); got != fallback {
		t.Fatalf("expected fallback version %q, got %q", fallback, got)
	}
}

func TestCurrentNormalizesTagPrefix(t *testing.T) {
	old := Version
	t.Cleanup(func() {
		Version = old
	})

	Version = "v1.2.3"

	if got := Current(); got != "1.2.3" {
		t.Fatalf("expected normalized version, got %q", got)
	}
	if got := Tag(); got != "v1.2.3" {
		t.Fatalf("expected tag version, got %q", got)
	}
}

func TestFallbackMatchesRepositoryVersionFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}

	if got := strings.TrimSpace(string(raw)); got != fallback {
		t.Fatalf("fallback version %q does not match VERSION file %q", fallback, got)
	}
}
