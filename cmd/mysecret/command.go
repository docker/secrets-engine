package main

import (
	"context"
	"fmt"

	"github.com/docker/cli/cli-plugins/plugin"
	"github.com/spf13/cobra"

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
			return plugin.PersistentPreRunE(cmd, args)
		},
		Version: fmt.Sprintf("%s, commit %s", config.Version, config.Commit()),
	}
	cmd.SetVersionTemplate("Docker MySecret Plugin\n{{.Version}}\n")
	cmd.Flags().BoolP("version", "v", false, "Print version information and quit")
	cmd.SetHelpTemplate(helpTemplate)

	_ = cmd.RegisterFlagCompletionFunc("mysecret", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"--help"}, cobra.ShellCompDirectiveNoFileComp
	})

	cmd.AddCommand(dummyCommand())

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
		RunE: func(*cobra.Command, []string) error {
			fmt.Println("hello")
			return nil
		},
	})

	return cmd
}
