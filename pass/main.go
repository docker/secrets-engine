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
	"go.opentelemetry.io/otel/codes"

	cmd "github.com/docker/secrets-engine/pass/command"
	"github.com/docker/secrets-engine/pass/service"
	"github.com/docker/secrets-engine/x/config"
	"github.com/docker/secrets-engine/x/oshelper"
)

func main() {
	ctx, span := cmd.Tracer().Start(context.Background(), "root")
	defer span.End()
	ctx, cancel := oshelper.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if plugin.RunningStandalone() {
		os.Args = append([]string{os.Args[0], "pass"}, os.Args[1:]...)
	}
	kc, err := service.KCService()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	plugin.Run(func(command.Cli) *cobra.Command {
		return cmd.PassCommand(ctx, kc)
	},
		manager.Metadata{
			SchemaVersion:    "0.1.0",
			Vendor:           "Docker Inc.",
			Version:          config.Version,
			ShortDescription: "Docker Pass Plugin",
		},
	)
}
