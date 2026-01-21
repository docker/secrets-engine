package runtime

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

const name = "github.com/docker/secrets-engine"

func tracer() trace.Tracer {
	return otel.Tracer(name)
}
