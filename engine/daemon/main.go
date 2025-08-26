package main

import (
	"context"
	"runtime/debug"
	"syscall"

	"github.com/docker/secrets-engine/engine"
	"github.com/docker/secrets-engine/engine/daemon/internal/dockerauth"
	"github.com/docker/secrets-engine/engine/daemon/internal/mysecret"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/oshelper"
	"github.com/docker/secrets-engine/x/secrets"
)

func main() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		panic("could not read build info")
	}
	version, err := api.NewVersion(bi.Main.Version)
	if err != nil {
		panic(err)
	}
	logger := logging.NewDefaultLogger("engine")
	mysecretPlugin, err := mysecret.NewMySecretPlugin(logger)
	if err != nil {
		panic(err)
	}
	dockerAuthPlugin, err := dockerauth.NewDockerAuthPlugin(logger)
	if err != nil {
		panic(err)
	}
	// TODO: double check if the version actually points to the engine sub-module or the main module
	e, err := engine.New("secrets-engine", bi.Main.Version,
		engine.WithLogger(logger),
		engine.WithPlugins(map[engine.Config]engine.Plugin{
			{Name: "mysecret", Version: version, Pattern: secrets.MustParsePattern("**")}:    mysecretPlugin,
			{Name: "docker-auth", Version: version, Pattern: secrets.MustParsePattern("**")}: dockerAuthPlugin,
		}),
		engine.WithEngineLaunchedPluginsDisabled(),
		// engine.WithExternallyLaunchedPluginsDisabled(),
	)
	if err != nil {
		panic(err)
	}

	ctx, cancel := oshelper.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := e.Run(ctx); err != nil {
		panic(err)
	}
}
