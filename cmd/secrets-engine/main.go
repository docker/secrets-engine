package main

import (
	"log/slog"
	"net/http"

	"github.com/docker/secrets-engine/pkg/engine"
)

func main() {
	engine := engine.NewEngine()

	http.Handle(engine.Handler())

	if err := http.ListenAndServe(":6666", nil); err != nil {
		slog.Error("listening", "err", err)
	}
}
