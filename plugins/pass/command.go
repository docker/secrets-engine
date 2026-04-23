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

const rootExample = `
### Using keychain secrets in containers

Create a secret:

` + "```" + `console
$ docker pass set GH_TOKEN=123456789
` + "```" + `

Create a secret from STDIN:

` + "```" + `console
echo "my_val" | docker pass set GH_TOKEN
` + "```" + `

Run a container that uses the secret:

` + "```" + `console
$ docker run -e GH_TOKEN= -dt --name demo busybox
` + "```" + `

Inspect the secret from inside the container:

` + "```" + `console
$ docker exec demo sh -c 'echo $GH_TOKEN'
123456789
` + "```" + `

Explicitly assign a secret to a different environment variable:

` + "```" + `console
$ docker run -e GITHUB_TOKEN=se://GH_TOKEN -dt --name demo busybox
` + "```" + `

### Using keychain secrets in Compose

Store the secrets:

` + "```" + `console
$ docker pass set myapp/anthropic/api-key=sk-ant-...
$ docker pass set myapp/postgres/password=s3cr3t
` + "```" + `

` + "```" + `yaml
services:
  api:
    image: service1
    environment:
      - ANTHROPIC_API_KEY=se://myapp/anthropic/api-key
      - POSTGRES_PASSWORD=se://myapp/postgres/password

  worker:
    image: service2
    command: worker
    environment:
      - ANTHROPIC_API_KEY=se://myapp/anthropic/api-key

  db:
    image: postgres:17
    environment:
      - POSTGRES_PASSWORD=se://myapp/postgres/password
` + "```"

// Root returns the root command for the docker-pass CLI plugin
func Root(ctx context.Context, s store.Store, info commands.VersionInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pass set|get|ls|rm",
		Short: "Manage your local OS keychain secrets.",
		Long: `Docker Pass is an experimental utility for managing secrets in your
local OS keychain. Secrets are stored using platform-specific credential
storage:

  - Windows: Windows Credential Manager API
  - macOS:   Keychain services API
  - Linux:   org.freedesktop.secrets API (requires DBus + gnome-keyring or kdewallet)

Secrets can be injected into running containers at runtime using the se:// URI scheme.`,
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

	cmd.AddCommand(wrapRunEWithSpan(commands.SetCommand(s)))
	cmd.AddCommand(wrapRunEWithSpan(commands.ListCommand(s)))
	cmd.AddCommand(wrapRunEWithSpan(commands.RmCommand(s)))
	cmd.AddCommand(wrapRunEWithSpan(commands.GetCommand(s)))
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
