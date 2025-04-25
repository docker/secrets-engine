package main

import (
	"log/slog"
	"net/http"
)

func main() {
	engine := NewEngine()

	http.Handle(Handler(engine))

	if err := http.ListenAndServe(":6666", nil); err != nil {
		slog.Error("listening", "err", err)
	}
}
