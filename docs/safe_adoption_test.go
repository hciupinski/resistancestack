package docs_test

import (
	"os"
	"strings"
	"testing"
)

func TestSafeAdoptionDocCoversMVP09Flow(t *testing.T) {
	raw, err := os.ReadFile("SAFE_ADOPTION.md")
	if err != nil {
		t.Fatalf("read safe adoption doc: %v", err)
	}
	doc := string(raw)
	for _, expected := range []string{
		"System Requirements",
		"resistack init",
		"resistack doctor --all",
		"resistack inventory",
		"resistack audit",
		"resistack apply host-hardening --dry-run",
		"resistack apply host-hardening",
		"Emergency VPS Access",
		"Avoiding SSH Lockout",
		"resistack rollback host --dry-run",
		"resistack rollback host",
		"MVP Limitations",
		"Read-Only vs Changing Commands",
		"Host-changing",
		"Repository-changing",
	} {
		if !strings.Contains(doc, expected) {
			t.Fatalf("expected safe adoption doc to contain %q", expected)
		}
	}
}
