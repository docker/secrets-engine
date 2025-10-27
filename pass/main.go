package main

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/docker/cli/cli-plugins/manager"
	"github.com/docker/cli/cli-plugins/plugin"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/pass/service"
	"github.com/docker/secrets-engine/x/config"
	"github.com/docker/secrets-engine/x/oshelper"
)

func main() {
	ctx, cancel := oshelper.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if plugin.RunningStandalone() {
		os.Args = append([]string{os.Args[0], "pass"}, os.Args[1:]...)
	}
	kc, err := service.KCService()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	plugin.Run(func(command.Cli) *cobra.Command {
		return rootCommand(ctx, kc)
	},
		manager.Metadata{
			SchemaVersion:    "0.1.0",
			Vendor:           "Docker Inc.",
			Version:          config.Version,
			ShortDescription: "Docker Pass Plugin",
		},
	)
}
