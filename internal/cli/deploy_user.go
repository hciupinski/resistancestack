package cli

import (
	"fmt"
	"io"

	"github.com/hciupinski/resistancestack/internal/deployuser"
)

func runDeployUser(args []string, out io.Writer, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("deploy-user requires a subcommand: check or bootstrap")
	}
	fs, configPath, envName := newConfigFlagSet("deploy-user " + args[0])
	user := fs.String("user", "", "Deploy user to check or bootstrap")
	connectAs := fs.String("connect-as", "", "SSH user used to connect before bootstrapping")
	publicKeyPath := fs.String("public-key-path", "", "Public key path to install or verify")
	dryRun := fs.Bool("dry-run", false, "Print the bootstrap script without executing it")
	selection, err := parseConfigSelection(fs, args[1:], configPath, envName)
	if err != nil {
		return err
	}
	ctx, err := loadContext(selection, out, errOut)
	if err != nil {
		return err
	}
	opts := deployuser.Options{
		User:          *user,
		ConnectAs:     *connectAs,
		PublicKeyPath: *publicKeyPath,
	}

	switch args[0] {
	case "check":
		return deployuser.Check(ctx.Config, opts, ctx.Out, ctx.ErrOut)
	case "bootstrap":
		return deployuser.Bootstrap(ctx.Config, opts, *dryRun, ctx.Out, ctx.ErrOut)
	default:
		return fmt.Errorf("unknown deploy-user subcommand %q", args[0])
	}
}
