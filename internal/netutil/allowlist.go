package netutil

import (
	"net/netip"
	"strings"
)

func IPInAllowlist(rawIP string, allowlist []string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return false
	}

	for _, entry := range allowlist {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(entry))
		if err != nil {
			continue
		}
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}
