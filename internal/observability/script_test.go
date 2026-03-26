package observability

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestBuildEnableScript_DefaultHash(t *testing.T) {
	cfg := config.Default("demo")
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(BuildEnableScript(cfg))))
	want := "e74847485bf47a672552cfd8c7d4bc4f2b80bbf5bfec679704b4854203ad9fb4"
	if got != want {
		t.Fatalf("unexpected enable script hash %s", got)
	}
}

func TestBuildDisableScript_DefaultHash(t *testing.T) {
	cfg := config.Default("demo")
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(BuildDisableScript(cfg))))
	want := "0604ee12cbd4dc42a5bf808112877e962a9c309ae36e20945ae78898597b420c"
	if got != want {
		t.Fatalf("unexpected disable script hash %s", got)
	}
}

func TestSplitBind_DefaultsAndIPv6(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort string
	}{
		{name: "empty", input: "", wantHost: "127.0.0.1", wantPort: "9400"},
		{name: "port only", input: ":9500", wantHost: "127.0.0.1", wantPort: "9500"},
		{name: "ipv4", input: "127.0.0.1:9600", wantHost: "127.0.0.1", wantPort: "9600"},
		{name: "ipv6", input: "::1:9700", wantHost: "::1", wantPort: "9700"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotPort := splitBind(tt.input)
			if gotHost != tt.wantHost || gotPort != tt.wantPort {
				t.Fatalf("splitBind(%q) = (%q, %q), want (%q, %q)", tt.input, gotHost, gotPort, tt.wantHost, tt.wantPort)
			}
		})
	}
}
