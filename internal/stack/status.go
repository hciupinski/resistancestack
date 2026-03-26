package stack

import (
	"io"

	"github.com/hciupinski/resistancestack/internal/audit"
	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/inventory"
)

func Status(cfg config.Config, root string, out io.Writer) error {
	snapshot, err := inventory.Collect(cfg, root)
	if err != nil {
		return err
	}
	report := audit.Evaluate(cfg, snapshot)

	_, err = io.WriteString(out, formatStatus(snapshot, report))
	if err != nil {
		return err
	}
	return nil
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
