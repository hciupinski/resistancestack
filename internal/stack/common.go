package stack

import (
	"fmt"
	"io"
)

type Module string

const (
	ModuleHostHardening         Module = "host-hardening"
	ModuleSecurityObservability Module = "security-observability"
	ModuleCISecurity            Module = "ci-security"
	ModuleInventoryAudit        Module = "inventory-audit"
)

func printWarnings(out io.Writer, warnings []string) {
	for _, warning := range warnings {
		fmt.Fprintf(out, "warning: %s\n", warning)
	}
}

func printErrors(out io.Writer, prefix string, errs []error) {
	for _, err := range errs {
		fmt.Fprintf(out, "%s: %v\n", prefix, err)
	}
}

func parseModules(values []string) ([]Module, error) {
	if len(values) == 0 {
		return []Module{ModuleHostHardening, ModuleSecurityObservability, ModuleCISecurity, ModuleInventoryAudit}, nil
	}
	modules := make([]Module, 0, len(values))
	for _, value := range values {
		module := Module(value)
		switch module {
		case ModuleHostHardening, ModuleSecurityObservability, ModuleCISecurity, ModuleInventoryAudit:
			modules = append(modules, module)
		default:
			return nil, fmt.Errorf("unknown module %q", value)
		}
	}
	return modules, nil
}
