package main

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/docker/cli/cli-plugins/metadata"
	"github.com/docker/cli/cli-plugins/plugin"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/codes"

	"github.com/docker/secrets-engine/plugins/pass"
	"github.com/docker/secrets-engine/plugins/pass/commands"
	"github.com/docker/secrets-engine/plugins/pass/store"
	"github.com/docker/secrets-engine/x/oshelper"
)

func main() {
	ctx, span := pass.Tracer().Start(context.Background(), "root")
	defer span.End()
	ctx, cancel := oshelper.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if plugin.RunningStandalone() {
		os.Args = append([]string{os.Args[0], "pass"}, os.Args[1:]...)
	}
	kc, err := store.PassStore("com.docker.docker-pass")
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	plugin.Run(func(command.Cli) *cobra.Command {
		return wrapPersistentPreRun(pass.Root(ctx, kc, commands.VersionInfo{Version: "dev", Commit: "main"}))
	},
		metadata.Metadata{
			SchemaVersion:    "0.1.0",
			Vendor:           "Docker Inc.",
			Version:          "dev",
			ShortDescription: "Docker Pass Plugin",
		},
	)
}

func wrapPersistentPreRun(cmd *cobra.Command) *cobra.Command {
	if plugin.PersistentPreRunE != nil {
		oldPreRunE := cmd.PersistentPreRunE
		cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
			if err := oldPreRunE(cmd, args); err != nil {
				return err
			}
			return plugin.PersistentPreRunE(cmd, args)
		}
	}
	return cmd
}
