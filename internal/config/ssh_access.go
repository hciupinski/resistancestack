package config

import "strings"

func ManagedSSHAllowUsers(cfg Config) []string {
	users := normalizeSSHUsers(cfg.HostHardening.SSHHardening.AllowUsers)
	if len(users) == 0 {
		return nil
	}
	if cfg.HostHardening.SSHHardening.GuardCurrentOperator {
		operator := strings.TrimSpace(cfg.Server.SSHUser)
		if operator != "" && !containsSSHUser(users, operator) {
			users = append(users, operator)
		}
	}
	return users
}

func FutureSSHLoginUsers(cfg Config) []string {
	candidates := ManagedSSHAllowUsers(cfg)
	if len(candidates) == 0 {
		operator := strings.TrimSpace(cfg.Server.SSHUser)
		if operator != "" {
			candidates = []string{operator}
		}
	}

	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if cfg.HostHardening.SSHHardening.DisableRootLogin && candidate == "root" {
			continue
		}
		result = append(result, candidate)
	}
	return result
}

func PreferredDeployUser(cfg Config) string {
	for _, candidate := range FutureSSHLoginUsers(cfg) {
		if candidate != "root" {
			return candidate
		}
	}
	return strings.TrimSpace(cfg.Server.SSHUser)
}

func normalizeSSHUsers(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || containsSSHUser(result, value) {
			continue
		}
		result = append(result, value)
	}
	return result
}

func containsSSHUser(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}
