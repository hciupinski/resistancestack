package hosthardening

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/netutil"
	"github.com/hciupinski/resistancestack/internal/remote"
)

type AccessPlan struct {
	Mode                   string
	CurrentOperatorIP      string
	PreserveCurrentSession bool
	StaticAllowlist        []string
	EffectiveAllowlist     []string
	BootstrapCIDR          string
	OpenSSHGlobally        bool
	BlockingReason         string
	FinalRuleModel         string
}

func PreviewAccessPlan(target remote.Target, cfg config.Config) (AccessPlan, error) {
	raw, err := remote.Capture(target, `printf '%s' "${SSH_CONNECTION:-}"`)
	if err != nil {
		return AccessPlan{}, err
	}
	currentIP, err := ParseCurrentOperatorIP(strings.TrimSpace(raw))
	if err != nil {
		return BuildAccessPlan(cfg, ""), err
	}
	return BuildAccessPlan(cfg, currentIP), nil
}

func ParseCurrentOperatorIP(raw string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return "", fmt.Errorf("SSH_CONNECTION is empty")
	}
	if len(fields) != 4 {
		return "", fmt.Errorf("SSH_CONNECTION must contain 4 tokens, got %d", len(fields))
	}
	addr, err := netip.ParseAddr(fields[0])
	if err != nil {
		return "", fmt.Errorf("parse SSH source IP: %w", err)
	}
	return addr.String(), nil
}

func BuildAccessPlan(cfg config.Config, currentOperatorIP string) AccessPlan {
	mode := cfg.HostHardening.UFWPolicy.OperatorAccessMode
	if strings.TrimSpace(mode) == "" {
		mode = config.OperatorAccessModePublicHardened
	}

	plan := AccessPlan{
		Mode:                   mode,
		CurrentOperatorIP:      strings.TrimSpace(currentOperatorIP),
		PreserveCurrentSession: cfg.HostHardening.UFWPolicy.PreserveCurrentSession,
		StaticAllowlist:        sanitizeAllowlist(cfg.HostHardening.UFWPolicy.AdminAllowlist),
	}
	plan.EffectiveAllowlist = append([]string{}, plan.StaticAllowlist...)

	currentIPValid := false
	if plan.CurrentOperatorIP != "" {
		_, err := netip.ParseAddr(plan.CurrentOperatorIP)
		currentIPValid = err == nil
	}

	if currentIPValid && plan.PreserveCurrentSession && !netutil.IPInAllowlist(plan.CurrentOperatorIP, plan.StaticAllowlist) {
		plan.BootstrapCIDR = cidrForIP(plan.CurrentOperatorIP)
		plan.EffectiveAllowlist = append(plan.EffectiveAllowlist, plan.BootstrapCIDR)
	}

	switch mode {
	case config.OperatorAccessModeAllowlistOnly:
		if !currentIPValid {
			plan.BlockingReason = "unable to derive current SSH client IP for allowlist_only mode"
		} else if len(plan.EffectiveAllowlist) == 0 {
			plan.BlockingReason = "no effective SSH allowlist available for allowlist_only mode"
		} else if !netutil.IPInAllowlist(plan.CurrentOperatorIP, plan.EffectiveAllowlist) {
			plan.BlockingReason = fmt.Sprintf("current SSH client IP %s is outside the effective allowlist", plan.CurrentOperatorIP)
		}
	default:
		if len(plan.StaticAllowlist) == 0 {
			plan.OpenSSHGlobally = true
		} else if plan.PreserveCurrentSession && !currentIPValid {
			plan.BlockingReason = "unable to derive current SSH client IP while preserve_current_session=true and static allowlist rules are configured"
		}
	}

	switch {
	case plan.OpenSSHGlobally:
		plan.FinalRuleModel = fmt.Sprintf("global SSH access on tcp/%d with key-only hardening", cfg.Server.SSHPort)
	case len(plan.StaticAllowlist) > 0:
		plan.FinalRuleModel = fmt.Sprintf("static allowlist on tcp/%d", cfg.Server.SSHPort)
	default:
		plan.FinalRuleModel = fmt.Sprintf("no static allowlist on tcp/%d", cfg.Server.SSHPort)
	}
	if plan.BootstrapCIDR != "" {
		plan.FinalRuleModel += fmt.Sprintf(" + bootstrap %s", plan.BootstrapCIDR)
	}
	if mode == config.OperatorAccessModeAllowlistOnly {
		plan.FinalRuleModel = "allowlist-only " + plan.FinalRuleModel
	}

	return plan
}

func FormatAccessPlan(plan AccessPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Host hardening access preview:\n")
	fmt.Fprintf(&b, "- operator access mode: %s\n", plan.Mode)
	if plan.CurrentOperatorIP == "" {
		fmt.Fprintf(&b, "- current source IP: unavailable\n")
	} else {
		fmt.Fprintf(&b, "- current source IP: %s\n", plan.CurrentOperatorIP)
	}
	fmt.Fprintf(&b, "- preserve current session: %t\n", plan.PreserveCurrentSession)
	if len(plan.StaticAllowlist) == 0 {
		fmt.Fprintf(&b, "- static admin allowlist: none\n")
	} else {
		fmt.Fprintf(&b, "- static admin allowlist: %s\n", strings.Join(plan.StaticAllowlist, ", "))
	}
	if plan.BootstrapCIDR == "" {
		fmt.Fprintf(&b, "- bootstrap current session: no\n")
	} else {
		fmt.Fprintf(&b, "- bootstrap current session: yes (%s)\n", plan.BootstrapCIDR)
	}
	fmt.Fprintf(&b, "- final SSH rule model: %s\n", plan.FinalRuleModel)
	if plan.BlockingReason != "" {
		fmt.Fprintf(&b, "- apply would fail: %s\n", plan.BlockingReason)
	}
	return strings.TrimRight(b.String(), "\n")
}
