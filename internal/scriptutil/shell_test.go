package scriptutil

import "testing"

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: "''"},
		{name: "plain", input: "value", want: "'value'"},
		{name: "single quote", input: "it's", want: `'it'"'"'s'`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShellQuote(tt.input); got != tt.want {
				t.Fatalf("ShellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
