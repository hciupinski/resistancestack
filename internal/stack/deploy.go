package stack

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hciupinski/resistancestack/internal/audit"
	"github.com/hciupinski/resistancestack/internal/ci"
	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/hosthardening"
	"github.com/hciupinski/resistancestack/internal/inventory"
	"github.com/hciupinski/resistancestack/internal/observability"
	"github.com/hciupinski/resistancestack/internal/preflight"
)

func Inventory(cfg config.Config, root string, out io.Writer) (inventory.Snapshot, error) {
	warnings, errs := preflight.CheckLocal(cfg, true)
	printWarnings(out, warnings)
	printErrors(out, "preflight error", errs)
	if len(errs) > 0 {
		return inventory.Snapshot{}, errors.New("preflight checks failed")
	}
	snapshot, err := inventory.Collect(cfg, root)
	if err != nil {
		return inventory.Snapshot{}, err
	}
	printInventory(out, snapshot)
	return snapshot, nil
}

func Audit(cfg config.Config, root string, dryRun bool, out io.Writer) (audit.Report, error) {
	if dryRun {
		fmt.Fprintln(out, "audit is read-only; proceeding in dry-run mode")
	}
	snapshot, err := inventory.Collect(cfg, root)
	if err != nil {
		return audit.Report{}, err
	}
	report := audit.Evaluate(cfg, snapshot)
	reportPath, err := audit.Save(root, cfg, report)
	if err != nil {
		return audit.Report{}, err
	}
	fmt.Fprintln(out, audit.FormatText(report))
	fmt.Fprintf(out, "Saved audit report to %s\n", reportPath)
	return report, nil
}

func Apply(cfg config.Config, root string, requestedModules []string, dryRun bool, out io.Writer, errOut io.Writer) error {
	warnings, errs := preflight.CheckLocal(cfg, true)
	printWarnings(out, warnings)
	printErrors(errOut, "preflight error", errs)
	if len(errs) > 0 {
		return errors.New("preflight checks failed")
	}

	modules, err := parseModules(requestedModules)
	if err != nil {
		return err
	}
	for _, module := range modules {
		switch module {
		case ModuleHostHardening:
			if err := hosthardening.Apply(cfg, dryRun, out, errOut); err != nil {
				return err
			}
		case ModuleSecurityObservability:
			if err := observability.Enable(cfg, dryRun, out, errOut); err != nil {
				return err
			}
		case ModuleCISecurity:
			if dryRun {
				expected, err := ci.Preview(root, cfg)
				if err != nil {
					return err
				}
				for _, wf := range expected {
					fmt.Fprintf(out, "would generate %s\n", wf.Path)
				}
				continue
			}
			paths, err := ci.Generate(root, cfg)
			if err != nil {
				return err
			}
			for _, path := range paths {
				fmt.Fprintf(out, "generated %s\n", path)
			}
		case ModuleInventoryAudit:
			report, err := Audit(cfg, root, dryRun, out)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "audit findings: %d\n", len(report.Findings))
		}
	}
	return nil
}

func RollbackHost(cfg config.Config, out io.Writer, errOut io.Writer) error {
	return hosthardening.Rollback(cfg, out, errOut)
}

func ValidateCI(cfg config.Config, root string, out io.Writer) error {
	result, err := ci.Validate(root, cfg)
	if err != nil {
		return err
	}
	if len(result.Missing) == 0 && len(result.Outdated) == 0 {
		fmt.Fprintln(out, "CI security workflows are present and up to date.")
		return nil
	}
	for _, missing := range result.Missing {
		fmt.Fprintf(out, "missing: %s\n", missing)
	}
	for _, outdated := range result.Outdated {
		fmt.Fprintf(out, "outdated: %s\n", outdated)
	}
	return errors.New("ci security workflows are missing or outdated")
}

func GenerateCI(cfg config.Config, root string, out io.Writer) error {
	paths, err := ci.Generate(root, cfg)
	if err != nil {
		return err
	}
	for _, path := range paths {
		fmt.Fprintf(out, "generated %s\n", path)
	}
	return nil
}

func printInventory(out io.Writer, snapshot inventory.Snapshot) {
	fmt.Fprintf(out, "Host: %s\n", snapshot.Host.Hostname)
	fmt.Fprintf(out, "OS: %s\n", snapshot.Host.OS)
	fmt.Fprintf(out, "Proxy: %s\n", snapshot.Proxy.Kind)
	fmt.Fprintf(out, "Runtime: %s\n", snapshot.Runtime.Kind)
	fmt.Fprintf(out, "UFW: %s\n", snapshot.UFW.Status)
	fmt.Fprintf(out, "Fail2ban: %s\n", snapshot.Fail2ban.Status)
	if len(snapshot.Repo.Technologies) > 0 {
		fmt.Fprintf(out, "Repo technologies: %s\n", stringsJoin(snapshot.Repo.Technologies))
	}
	if len(snapshot.Repo.GitHubWorkflows) > 0 {
		fmt.Fprintf(out, "GitHub workflows: %s\n", stringsJoin(snapshot.Repo.GitHubWorkflows))
	}
}

func stringsJoin(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}
