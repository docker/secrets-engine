package main

import (
	"context"
	"runtime/debug"

	"github.com/docker/secrets-engine/engine"
	"github.com/docker/secrets-engine/internal/oshelper"
)

func main() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		panic("could not read build info")
	}
	// TODO: double check if the version actually points to the engine sub-module or the main module
	e, err := engine.New("secrets-engine", bi.Main.Version,
		engine.WithEngineLaunchedPluginsDisabled(),
		engine.WithExternallyLaunchedPluginsDisabled(),
	)
	if err != nil {
		panic(err)
	}

	ctx, cancel := oshelper.NotifyContext(context.Background())
	defer cancel()

	if err := e.Run(ctx); err != nil {
		panic(err)
	}
}
