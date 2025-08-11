package main

import (
	"context"
	"runtime/debug"

	"github.com/docker/secrets-engine/engine"
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

	if err := e.Run(context.Background()); err != nil {
		panic(err)
	}
}
