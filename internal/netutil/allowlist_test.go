package netutil

import "testing"

func TestIPInAllowlist(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		allowlist []string
		want      bool
	}{
		{name: "ipv4 match", ip: "203.0.113.10", allowlist: []string{"203.0.113.0/24"}, want: true},
		{name: "ipv4 miss", ip: "203.0.114.10", allowlist: []string{"203.0.113.0/24"}, want: false},
		{name: "invalid ip", ip: "bad", allowlist: []string{"203.0.113.0/24"}, want: false},
		{name: "invalid prefix ignored", ip: "203.0.113.10", allowlist: []string{"bad", "203.0.113.10/32"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IPInAllowlist(tt.ip, tt.allowlist); got != tt.want {
				t.Fatalf("IPInAllowlist(%q, %v) = %t, want %t", tt.ip, tt.allowlist, got, tt.want)
			}
		})
	}
}
