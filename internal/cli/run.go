package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hciupinski/resistancestack/internal/config"
	"github.com/hciupinski/resistancestack/internal/deployuser"
	"github.com/hciupinski/resistancestack/internal/doctor"
	"github.com/hciupinski/resistancestack/internal/observability"
	"github.com/hciupinski/resistancestack/internal/stack"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	viperKeyConfig         = "config"
	viperKeyEnv            = "env"
	viperKeyOutput         = "output"
	viperKeyVerbose        = "verbose"
	viperKeyNonInteractive = "non-interactive"
)

var errNotImplemented = errors.New("not implemented")

var Version = "dev"

type rootOptions struct {
	configPath     string
	envName        string
	outputFormat   string
	verbose        bool
	nonInteractive bool
}

func Run(args []string, out io.Writer, errOut io.Writer) error {
	cmd := NewRootCommand(out, errOut)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func NewRootCommand(out io.Writer, errOut io.Writer) *cobra.Command {
	opts := rootOptions{}
	v := viper.New()
	v.SetEnvPrefix("RESISTACK")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	v.SetDefault(viperKeyConfig, defaultConfigPath)
	v.SetDefault(viperKeyOutput, config.FormatText)
	v.SetDefault(viperKeyEnv, "")
	v.SetDefault(viperKeyVerbose, false)
	v.SetDefault(viperKeyNonInteractive, false)

	root := &cobra.Command{
		Use:           "resistack",
		Short:         "ResistanceStack v2 CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	root.SetOut(out)
	root.SetErr(errOut)

	flags := root.PersistentFlags()
	flags.StringVar(&opts.configPath, viperKeyConfig, defaultConfigPath, "Base configuration file")
	flags.StringVar(&opts.envName, viperKeyEnv, "", "Environment overlay name, resolved as resistack.<env>.yaml")
	flags.StringVar(&opts.outputFormat, viperKeyOutput, config.FormatText, "Output format for commands that support structured output")
	flags.BoolVar(&opts.verbose, viperKeyVerbose, false, "Enable verbose diagnostic output")
	flags.BoolVar(&opts.nonInteractive, "non-interactive", false, "Disable interactive prompts")

	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		opts.configPath = strings.TrimSpace(stringOption(cmd, v, viperKeyConfig, defaultConfigPath))
		if opts.configPath == "" {
			opts.configPath = defaultConfigPath
		}
		opts.envName = strings.TrimSpace(stringOption(cmd, v, viperKeyEnv, ""))
		opts.outputFormat = strings.TrimSpace(stringOption(cmd, v, viperKeyOutput, config.FormatText))
		if opts.outputFormat == "" {
			opts.outputFormat = config.FormatText
		}
		opts.verbose = boolOption(cmd, v, viperKeyVerbose, false)
		opts.nonInteractive = boolOption(cmd, v, viperKeyNonInteractive, false)
		return config.ValidateEnvName(opts.envName)
	}

	root.AddCommand(
		newInitCommand(&opts, out),
		newWizardCommand(),
		newDoctorCommand(&opts, out, errOut),
		newInventoryCommand(&opts, out, errOut),
		newAuditCommand(&opts, out, errOut),
		newApplyCommand(&opts, out, errOut),
		newStatusCommand(&opts, out, errOut),
		newDeployUserCommand(&opts, out, errOut),
		newCICommand(&opts, out, errOut),
		newObservabilityCommand(&opts, out, errOut),
		newRollbackCommand(&opts, out, errOut),
	)

	return root
}

func newInitCommand(opts *rootOptions, out io.Writer) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init [project-name]",
		Short: "Generate or update resistack.yaml",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projectName := ""
			if len(args) > 0 {
				projectName = args[0]
			}
			if projectName == "" {
				wd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("resolve working directory: %w", err)
				}
				projectName = filepath.Base(wd)
			}

			result, err := config.EnsureDefaultConfig(opts.configPath, projectName, force)
			if err != nil {
				return err
			}
			switch {
			case result.Created && force:
				fmt.Fprintf(out, "Overwrote %s with the latest security baseline defaults for project %q\n", opts.configPath, projectName)
			case result.Created:
				fmt.Fprintf(out, "Created %s for security baseline project %q\n", opts.configPath, projectName)
			case len(result.Added) > 0:
				fmt.Fprintf(out, "Updated %s with %d new configuration defaults for project %q: %s\n", opts.configPath, len(result.Added), projectName, strings.Join(result.Added, ", "))
			default:
				fmt.Fprintf(out, "%s is already up to date for project %q\n", opts.configPath, projectName)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing configuration file")
	return cmd
}

func newWizardCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "wizard",
		Short: "Interactively create a ResistanceStack configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("wizard command: %w; planned for MVP-04", errNotImplemented)
		},
	}
}

func newDoctorCommand(opts *rootOptions, out io.Writer, errOut io.Writer) *cobra.Command {
	var local bool
	var remoteOnly bool
	var all bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local and remote compatibility before applying changes",
		RunE: func(cmd *cobra.Command, args []string) error {
			selected := 0
			for _, enabled := range []bool{local, remoteOnly, all} {
				if enabled {
					selected++
				}
			}
			if selected > 1 {
				return fmt.Errorf("doctor accepts only one of --local, --remote, or --all")
			}
			mode := doctor.ModeAll
			switch {
			case local:
				mode = doctor.ModeLocal
			case remoteOnly:
				mode = doctor.ModeRemote
			case all:
				mode = doctor.ModeAll
			}

			selection := opts.selection()
			selection.Local = true
			ctx, err := loadContext(selection, out, errOut)
			if err != nil {
				return err
			}
			report, err := stack.Doctor(ctx.Config, ctx.Root, doctor.Options{Mode: mode, Version: Version}, ctx.Out)
			if err != nil {
				return err
			}
			if report.HasFailures() {
				return fmt.Errorf("doctor checks failed")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&local, "local", false, "Check local prerequisites only")
	cmd.Flags().BoolVar(&remoteOnly, "remote", false, "Check remote host prerequisites only")
	cmd.Flags().BoolVar(&all, "all", false, "Check local and remote prerequisites")
	return cmd
}

func newInventoryCommand(opts *rootOptions, out io.Writer, errOut io.Writer) *cobra.Command {
	var local bool
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Detect current VPS and repository state",
		RunE: func(cmd *cobra.Command, args []string) error {
			selection := opts.selection()
			selection.Local = local
			ctx, err := loadContext(selection, out, errOut)
			if err != nil {
				return err
			}
			if local {
				_, err = stack.InventoryLocal(ctx.Config, ctx.Root, ctx.Out)
				return err
			}
			_, err = stack.Inventory(ctx.Config, ctx.Root, ctx.Out)
			return err
		},
	}
	cmd.Flags().BoolVar(&local, "local", false, "Inspect repository evidence without opening an SSH connection")
	return cmd
}

func newAuditCommand(opts *rootOptions, out io.Writer, errOut io.Writer) *cobra.Command {
	var dryRun bool
	var local bool
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Generate risk report and remediation plan",
		RunE: func(cmd *cobra.Command, args []string) error {
			selection := opts.selection()
			selection.Local = local
			ctx, err := loadContext(selection, out, errOut)
			if err != nil {
				return err
			}
			if local {
				_, err = stack.AuditLocal(ctx.Config, ctx.Root, dryRun, ctx.Out)
				return err
			}
			_, err = stack.Audit(ctx.Config, ctx.Root, dryRun, ctx.Out)
			return err
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Explain what audit will do while keeping the read-only execution path")
	cmd.Flags().BoolVar(&local, "local", false, "Inspect repository evidence without opening an SSH connection")
	return cmd
}

func newApplyCommand(opts *rootOptions, out io.Writer, errOut io.Writer) *cobra.Command {
	var dryRun bool
	var forceWithRiskAcceptance bool
	cmd := &cobra.Command{
		Use:   "apply [modules...]",
		Short: "Apply selected security modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(opts.selection(), out, errOut)
			if err != nil {
				return err
			}
			return stack.Apply(ctx.Config, ctx.Root, args, dryRun, forceWithRiskAcceptance, ctx.Out, ctx.ErrOut)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print intended changes without executing them")
	cmd.Flags().BoolVar(&forceWithRiskAcceptance, "force-with-risk-acceptance", false, "Bypass failing doctor checks before host-hardening")
	return cmd
}

func newStatusCommand(opts *rootOptions, out io.Writer, errOut io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show host, observability, and security posture",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(opts.selection(), out, errOut)
			if err != nil {
				return err
			}
			return stack.Status(ctx.Config, ctx.Root, ctx.Out)
		},
	}
}

func newDeployUserCommand(opts *rootOptions, out io.Writer, errOut io.Writer) *cobra.Command {
	parent := &cobra.Command{
		Use:   "deploy-user",
		Short: "Verify or bootstrap the future SSH deploy user",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("deploy-user requires a subcommand: check or bootstrap")
		},
	}

	var user string
	var connectAs string
	var publicKeyPath string
	var dryRun bool
	addDeployFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringVar(&user, "user", "", "Deploy user to check or bootstrap")
		cmd.Flags().StringVar(&connectAs, "connect-as", "", "SSH user used to connect before bootstrapping")
		cmd.Flags().StringVar(&publicKeyPath, "public-key-path", "", "Public key path to install or verify")
	}
	optsForRun := func() deployuser.Options {
		return deployuser.Options{User: user, ConnectAs: connectAs, PublicKeyPath: publicKeyPath}
	}

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Verify that the deploy user is ready",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(opts.selection(), out, errOut)
			if err != nil {
				return err
			}
			return deployuser.Check(ctx.Config, optsForRun(), ctx.Out, ctx.ErrOut)
		},
	}
	addDeployFlags(checkCmd)

	bootstrapCmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap the future SSH deploy user",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(opts.selection(), out, errOut)
			if err != nil {
				return err
			}
			return deployuser.Bootstrap(ctx.Config, optsForRun(), dryRun, ctx.Out, ctx.ErrOut)
		},
	}
	addDeployFlags(bootstrapCmd)
	bootstrapCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the bootstrap script without executing it")

	parent.AddCommand(checkCmd, bootstrapCmd)
	return parent
}

func newCICommand(opts *rootOptions, out io.Writer, errOut io.Writer) *cobra.Command {
	parent := &cobra.Command{
		Use:   "ci",
		Short: "Generate or validate standalone security workflows",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("ci requires a subcommand: generate or validate")
		},
	}
	parent.AddCommand(
		&cobra.Command{
			Use:   "generate",
			Short: "Generate standalone security workflows",
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx, err := loadContext(opts.selection(), out, errOut)
				if err != nil {
					return err
				}
				return stack.GenerateCI(ctx.Config, ctx.Root, ctx.Out)
			},
		},
		&cobra.Command{
			Use:   "validate",
			Short: "Validate generated security workflows",
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx, err := loadContext(opts.selection(), out, errOut)
				if err != nil {
					return err
				}
				return stack.ValidateCI(ctx.Config, ctx.Root, ctx.Out)
			},
		},
	)
	return parent
}

func newObservabilityCommand(opts *rootOptions, out io.Writer, errOut io.Writer) *cobra.Command {
	parent := &cobra.Command{
		Use:   "observability",
		Short: "Manage local security observability baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("observability requires a subcommand: enable or disable")
		},
	}
	var dryRun bool
	enableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable local observability baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(opts.selection(), out, errOut)
			if err != nil {
				return err
			}
			return observability.Enable(ctx.Config, dryRun, ctx.Out, ctx.ErrOut)
		},
	}
	enableCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the observability changes without executing them")

	disableCmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable local observability baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(opts.selection(), out, errOut)
			if err != nil {
				return err
			}
			return observability.Disable(ctx.Config, ctx.Out, ctx.ErrOut)
		},
	}
	parent.AddCommand(enableCmd, disableCmd)
	return parent
}

func newRollbackCommand(opts *rootOptions, out io.Writer, errOut io.Writer) *cobra.Command {
	parent := &cobra.Command{
		Use:   "rollback",
		Short: "Roll back managed changes",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("rollback requires a subcommand: host")
		},
	}
	parent.AddCommand(&cobra.Command{
		Use:   "host",
		Short: "Roll back the last host-hardening change",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, err := loadContext(opts.selection(), out, errOut)
			if err != nil {
				return err
			}
			return stack.RollbackHost(ctx.Config, ctx.Out, ctx.ErrOut)
		},
	})
	return parent
}

func (o rootOptions) selection() ConfigSelection {
	return ConfigSelection{ConfigPath: o.configPath, Env: o.envName, OutputFormat: o.outputFormat}
}

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, errNotImplemented) {
		return 2
	}
	return 1
}

func stringOption(cmd *cobra.Command, v *viper.Viper, flagName string, defaultValue string) string {
	flag := cmd.Root().PersistentFlags().Lookup(flagName)
	if flag != nil && flag.Changed {
		return flag.Value.String()
	}
	if value := strings.TrimSpace(v.GetString(flagName)); value != "" {
		return value
	}
	return defaultValue
}

func boolOption(cmd *cobra.Command, v *viper.Viper, flagName string, defaultValue bool) bool {
	flag := cmd.Root().PersistentFlags().Lookup(flagName)
	if flag != nil && flag.Changed {
		return flag.Value.String() == "true"
	}
	v.SetDefault(flagName, defaultValue)
	return v.GetBool(flagName)
}
