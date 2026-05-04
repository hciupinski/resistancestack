package stack

import (
	"errors"
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/audit"
	"github.com/hciupinski/resistancestack/internal/ci"
	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/doctor"
	"github.com/hciupinski/resistancestack/internal/hosthardening"
	"github.com/hciupinski/resistancestack/internal/inventory"
	"github.com/hciupinski/resistancestack/internal/observability"
	"github.com/hciupinski/resistancestack/internal/preflight"
)

var runDoctor = doctor.Run

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
	renderInventory(out, snapshot)
	return snapshot, nil
}

func InventoryLocal(cfg config.Config, root string, out io.Writer) (inventory.Snapshot, error) {
	warnings, errs := preflight.CheckLocal(cfg, false)
	printWarnings(out, warnings)
	printErrors(out, "preflight error", errs)
	if len(errs) > 0 {
		return inventory.Snapshot{}, errors.New("preflight checks failed")
	}
	snapshot, err := inventory.CollectLocal(cfg, root)
	if err != nil {
		return inventory.Snapshot{}, err
	}
	renderInventory(out, snapshot)
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

func AuditLocal(cfg config.Config, root string, dryRun bool, out io.Writer) (audit.Report, error) {
	if dryRun {
		fmt.Fprintln(out, "audit is read-only; proceeding in dry-run mode")
	}
	snapshot, err := inventory.CollectLocal(cfg, root)
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

func Doctor(cfg config.Config, root string, opts doctor.Options, out io.Writer) (doctor.Report, error) {
	report, err := doctor.Run(cfg, root, opts)
	if err != nil {
		return doctor.Report{}, err
	}
	reportPath, err := doctor.Save(root, cfg, report)
	if err != nil {
		return doctor.Report{}, err
	}
	if cfg.Reporting.Format == config.FormatJSON {
		raw, err := doctor.FormatJSON(report)
		if err != nil {
			return doctor.Report{}, err
		}
		fmt.Fprintln(out, string(raw))
	} else {
		fmt.Fprintln(out, doctor.FormatText(report))
	}
	fmt.Fprintf(out, "Saved doctor report to %s\n", reportPath)
	return report, nil
}

func Apply(cfg config.Config, root string, requestedModules []string, dryRun bool, forceWithRiskAcceptance bool, out io.Writer, errOut io.Writer) error {
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
	if !dryRun && !forceWithRiskAcceptance && containsModule(modules, ModuleHostHardening) {
		report, err := runDoctor(cfg, root, doctor.Options{Mode: doctor.ModeAll, Version: "dev"})
		if err != nil {
			return err
		}
		if report.HasFailures() {
			fmt.Fprintln(errOut, doctor.FormatText(report))
			return errors.New("doctor checks failed; run `resistack doctor --all` or pass `--force-with-risk-acceptance` to apply host-hardening anyway")
		}
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

func containsModule(modules []Module, expected Module) bool {
	for _, module := range modules {
		if module == expected {
			return true
		}
	}
	return false
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
