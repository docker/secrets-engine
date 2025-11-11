package commands

import (
	"runtime/debug"
	"sync"

	"github.com/spf13/cobra"
)

var commit = sync.OnceValue(func() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range bi.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}

	return "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
})

func VersionCommand(version string) *cobra.Command {
	return &cobra.Command{
		Short:  "Show the version information",
		Use:    "version",
		Hidden: true,
		Args:   cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Printf("Version: %s\nCommit: %s\n", version, commit())
		},
	}
}
