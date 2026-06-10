// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pass

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/term"

	"github.com/docker/secrets-engine/plugins/pass/commands"
	"github.com/docker/secrets-engine/store"
)

// StoreFactory opens the backing keychain store on demand. Subcommands invoke
// it from their RunE so that commands which never touch the store (version,
// help, completion) do not pay the keychain-init cost — and do not hang in
// headless environments where no D-Bus session bus is reachable.
type StoreFactory func() (store.Store, error)

// Note: We use a custom help template to make it more brief.
const helpTemplate = `Docker Pass CLI - Manage your local secrets.
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

//go:embed examples.md
var rootExample string

//go:embed long.md
var rootLong string

// Root returns the root command for the docker-pass CLI plugin.
//
// newStore is invoked lazily by subcommands that need keychain access. Commands
// that do not touch the store (version, help, completion) never call it, so the
// binary stays usable in headless environments where opening the keychain would
// hang on a missing D-Bus session bus.
func Root(ctx context.Context, newStore StoreFactory, info commands.VersionInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:              "pass set|get|ls|rm|run",
		Short:            "Manage your local OS keychain secrets.",
		Long:             strings.TrimSpace(rootLong),
		Example:          strings.TrimSpace(rootExample),
		SilenceUsage:     true,
		TraverseChildren: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: false,
			HiddenDefaultCmd:  true,
		},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SetContext(ctx)
			return nil
		},
	}
	cmd.SetHelpTemplate(helpTemplate)

	_ = cmd.RegisterFlagCompletionFunc("pass", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"--help"}, cobra.ShellCompDirectiveNoFileComp
	})

	cmd.AddCommand(wrapRunEWithSpan(commands.SetCommand(newStore)))
	cmd.AddCommand(wrapRunEWithSpan(commands.ListCommand(newStore)))
	cmd.AddCommand(wrapRunEWithSpan(commands.RmCommand(newStore)))
	cmd.AddCommand(wrapRunEWithSpan(commands.GetCommand(newStore)))
	cmd.AddCommand(wrapRunEWithSpan(commands.RunCommand()))
	cmd.AddCommand(commands.VersionCommand(info))

	return cmd
}

const (
	meterName  = "github.com/docker/secrets-engine/plugins/pass"
	tracerName = "github.com/docker/secrets-engine/plugins/pass"
)

func int64counter(counter string, opts ...metric.Int64CounterOption) metric.Int64Counter {
	reqs, err := otel.GetMeterProvider().Meter(meterName).Int64Counter(counter, opts...)
	if err != nil {
		otel.Handle(err)
		reqs, _ = noop.NewMeterProvider().Meter(meterName).Int64Counter(counter, opts...)
	}
	return reqs
}

func Tracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer(tracerName)
}

func wrapRunEWithSpan(cmd *cobra.Command) *cobra.Command {
	cmd.RunE = withOTEL(cmd.RunE)
	return cmd
}

func withOTEL(runE func(cmd *cobra.Command, args []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx, span := Tracer().Start(cmd.Context(), "secrets.pass.called",
			trace.WithSpanKind(trace.SpanKindInternal),
			trace.WithAttributes(attribute.String("command", cmd.Name())),
		)

		pendingExit := -1
		defer func() {
			if pendingExit >= 0 {
				os.Exit(pendingExit)
			}
		}()
		defer span.End()

		cmd.SetContext(ctx)
		err := runE(cmd, args)

		var exitErr *commands.ExitCodeError
		if errors.As(err, &exitErr) {
			pendingExit = exitErr.Code
			span.SetAttributes(attribute.Int("command.child_exit_code", exitErr.Code))
			span.SetStatus(codes.Ok, "child exited")
			calledMetric(ctx, cmd, nil)
			return nil
		}

		calledMetric(ctx, cmd, err)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		span.SetStatus(codes.Ok, "success")
		return nil
	}
}

func calledMetric(ctx context.Context, cmd *cobra.Command, err error) {
	counter := int64counter("secrets.pass.called",
		metric.WithDescription("docker-pass called"),
		metric.WithUnit("invocation"),
	)
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	counter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("command", cmd.Name()),
		attribute.String("error", errMsg),
		attribute.Bool("tty", term.IsTerminal(int(os.Stdout.Fd()))),
	))
}
