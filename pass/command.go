package pass

import (
	"context"
	"fmt"
	"os"

	"github.com/docker/cli/cli-plugins/plugin"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/term"

	"github.com/docker/secrets-engine/pass/commands"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/config"
)

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

// Root returns the root command for the docker-pass CLI plugin
func Root(ctx context.Context, s store.Store) *cobra.Command {
	cmd := &cobra.Command{
		Use:              "pass [OPTIONS]",
		SilenceUsage:     true,
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
	cmd.SetVersionTemplate("Docker Pass Plugin\n{{.Version}}\n")
	cmd.Flags().BoolP("version", "v", false, "Print version information and quit")
	cmd.SetHelpTemplate(helpTemplate)

	_ = cmd.RegisterFlagCompletionFunc("pass", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"--help"}, cobra.ShellCompDirectiveNoFileComp
	})

	cmd.AddCommand(wrapRunEWithSpan(commands.SetCommand(s)))
	cmd.AddCommand(wrapRunEWithSpan(commands.ListCommand(s)))
	cmd.AddCommand(wrapRunEWithSpan(commands.RmCommand(s)))
	cmd.AddCommand(wrapRunEWithSpan(commands.GetCommand(s)))

	return cmd
}

const (
	meterName  = "github.com/docker/secrets-engine/pass"
	tracerName = "github.com/docker/secrets-engine/pass"
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
		defer span.End()
		cmd.SetContext(ctx)
		err := runE(cmd, args)
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
