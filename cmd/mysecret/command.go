package main

import (
	"context"
	"fmt"

	"github.com/docker/cli/cli-plugins/plugin"
	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/cmd/mysecret/internal/project"
	"github.com/docker/secrets-engine/internal/config"
)

// Note: We use a custom help template to make it more brief.
const helpTemplate = `Docker MySecret CLI - Manage your local secrets.
{{if .UseLine}}
Usage: {{.UseLine}}
{{end}}{{if .HasAvailableLocalFlags}}
Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
{{end}}{{if .HasAvailableSubCommands}}
Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand)}}  {{rpad .Name .NamePadding }} {{.Short}}
{{end}}{{end}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}
`

// rootCommand returns the root command for the init plugin
func rootCommand(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:              "mysecret [OPTIONS]",
		TraverseChildren: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: false,
			HiddenDefaultCmd:  true,
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cmd.SetContext(ctx)
			if plugin.PersistentPreRunE != nil {
				return plugin.PersistentPreRunE(cmd, args)
			}
			return nil
		},
		Version: fmt.Sprintf("%s, commit %s", config.Version, config.Commit()),
	}
	cmd.SetVersionTemplate("Docker MySecret Plugin\n{{.Version}}\n")
	cmd.Flags().BoolP("version", "v", false, "Print version information and quit")
	cmd.SetHelpTemplate(helpTemplate)

	_ = cmd.RegisterFlagCompletionFunc("mysecret", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"--help"}, cobra.ShellCompDirectiveNoFileComp
	})

	return cmd
}

func mySecretCommands(ctx context.Context) *cobra.Command {
	root := rootCommand(ctx)
	root.AddCommand(WithProjectContextHandling(dummyCommand()))
	return root
}

func WithProjectContextHandling(cmd *cobra.Command) *cobra.Command {
	var global bool
	origPersistentPreRun := cmd.PersistentPreRunE
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if !global {
			proj, err := project.CurrentGitProject()
			if err != nil {
				return err
			}
			ctx = project.WithProject(ctx, proj)
		}
		cmd.SetContext(ctx)
		if origPersistentPreRun != nil {
			return origPersistentPreRun(cmd, args)
		}
		return nil
	}
	cmd.Flags().BoolVarP(&global, "global", "g", false, "global (no project realm)")
	return cmd
}

func dummyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dummy",
		Short: "just a test",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "read",
		Short: "Read the configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if proj, err := project.FromContext(ctx); err == nil {
				fmt.Printf("in project: %s\n", proj)
			} else {
				fmt.Println("no project (global)")
			}
			fmt.Println("hello")

			return nil
		},
	})

	return cmd
}
