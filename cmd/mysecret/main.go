package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/docker/cli/cli-plugins/manager"
	"github.com/docker/cli/cli-plugins/plugin"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"

	"github.com/docker/secrets-engine/internal/config"
)

type errCtxSignalTerminated struct {
	signal os.Signal
}

func (errCtxSignalTerminated) Error() string {
	return ""
}

func main() {
	ctx, cancel := notifyContext(context.Background())
	defer cancel()
	if plugin.RunningStandalone() {
		os.Args = append([]string{os.Args[0], "mysecret"}, os.Args[1:]...)
	}

	plugin.Run(func(command.Cli) *cobra.Command {
		return mySecretCommands(ctx)
	},
		manager.Metadata{
			SchemaVersion:    "0.1.0",
			Vendor:           "Docker Inc.",
			Version:          config.Version,
			ShortDescription: "Docker MySecret Plugin",
		},
	)
}

func notifyContext(ctx context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, signals...)

	ctxCause, cancel := context.WithCancelCause(ctx)

	go func() {
		select {
		case <-ctx.Done():
			signal.Stop(ch)
			return
		case sig := <-ch:
			cancel(errCtxSignalTerminated{signal: sig})
			signal.Stop(ch)
			return
		}
	}()

	return ctxCause, func() {
		signal.Stop(ch)
		cancel(nil)
	}
}
