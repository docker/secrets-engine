package main

import (
	"context"
	"os"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/docker/secrets-engine/engine"
	"github.com/docker/secrets-engine/engine/builtins/dockerauth"
	"github.com/docker/secrets-engine/engine/builtins/pass"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/oshelper"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/telemetry"
)

func main() {
	ctx, cancel := oshelper.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	logger := logging.NewDefaultLogger("engine")
	ctx = logging.WithLogger(ctx, logger)

	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); endpoint != "" {
		shutdown, err := telemetry.InitializeOTel(ctx, endpoint)
		if err != nil {
			panic(err)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 100*time.Millisecond)
			defer cancel()
			shutdown(ctx)
		}()
	} else {
		logger.Printf("No OTLP endpoint defined, tracing will not be enabled")
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		panic("could not read build info")
	}
	buildVersion := bi.Main.Version
	// on untagged branches, the version could be "(devel)"
	if buildVersion == "(devel)" {
		buildVersion = "v0.0.0-dev"
	}
	version, err := api.NewVersion(buildVersion)
	if err != nil {
		panic(err)
	}

	passPlugin, err := pass.NewPassPlugin(logger)
	if err != nil {
		panic(err)
	}
	dockerAuthPlugin, err := dockerauth.NewDockerAuthPlugin(logger)
	if err != nil {
		panic(err)
	}

	opts := []engine.Option{
		engine.WithLogger(logger),
		engine.WithPlugins(map[engine.Config]engine.Plugin{
			{Name: "docker-pass", Version: version, Pattern: secrets.MustParsePattern("**")}: passPlugin,
			{Name: "docker-auth", Version: version, Pattern: secrets.MustParsePattern("**")}: dockerAuthPlugin,
		}),
		engine.WithEngineLaunchedPluginsDisabled(),
		// engine.WithExternallyLaunchedPluginsDisabled(),
	}

	// TODO: double check if the version actually points to the engine sub-module or the main module
	if err := engine.Run(ctx, "secrets-engine", bi.Main.Version, opts...); err != nil {
		panic(err)
	}
}
