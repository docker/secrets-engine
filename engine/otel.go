package engine

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

const name = "secrets-engine"

func int64counter(counter string, opts ...metric.Int64CounterOption) metric.Int64Counter {
	reqs, err := otel.Meter(name).Int64Counter(counter, opts...)
	if err != nil {
		otel.Handle(err)
		reqs, _ = noop.NewMeterProvider().Meter(name).Int64Counter(counter, opts...)
	}
	return reqs
}
