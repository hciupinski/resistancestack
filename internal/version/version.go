package version

import "strings"

const fallback = "0.1.1"

// Version is overridden by release builds through -ldflags.
var Version = fallback

func Current() string {
	version := strings.TrimSpace(Version)
	if version == "" {
		return fallback
	}
	return strings.TrimPrefix(version, "v")
}

func Tag() string {
	return "v" + Current()
}
