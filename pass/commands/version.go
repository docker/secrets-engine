package commands

import (
	"github.com/spf13/cobra"
)

type VersionInfo struct {
	Version string
	Commit  string
}

func VersionCommand(info VersionInfo) *cobra.Command {
	return &cobra.Command{
		Short:  "Show the version information",
		Use:    "version",
		Hidden: true,
		Args:   cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Printf("Version: %s\nCommit: %s\n", info.Version, info.Commit)
		},
	}
}
