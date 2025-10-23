package engine

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

var _ secrets.Resolver = &regResolver{}

type regResolver struct {
	reg      registry
	logger   logging.Logger
	reqTotal metric.Int64Counter
	reqEmpty metric.Int64Counter
}

func newRegResolver(logger logging.Logger, reg registry) *regResolver {
	return &regResolver{
		reg:    reg,
		logger: logger,
		reqTotal: int64counter("secrets.requests.total",
			metric.WithDescription("Total secret requests processed by the engine."),
			metric.WithUnit("{request}")),
		reqEmpty: int64counter("secrets.requests.empty",
			metric.WithDescription("Total secret requests processed by the engine that returned no results."),
			metric.WithUnit("{request}")),
	}
}

func (r regResolver) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	r.reqTotal.Add(ctx, 1)

	var results []secrets.Envelope

	for plugin := range r.reg.Iterator() {
		if !plugin.Pattern().Includes(pattern) {
			continue
		}

		envelopes, err := plugin.GetSecrets(ctx, pattern)
		if err != nil {
			if !errors.Is(err, secrets.ErrNotFound) {
				r.logger.Errorf("plugin '%s': %s", plugin.Name(), err)
			}
			continue
		}

		for _, envelope := range envelopes {
			envelope.Provider = plugin.Name().String()
			if envelope.ResolvedAt.IsZero() {
				envelope.ResolvedAt = time.Now().UTC()
			}
			results = append(results, envelope)
		}
	}

	if len(results) > 0 {
		return results, nil
	}

	r.reqEmpty.Add(ctx, 1)
	return results, secrets.ErrNotFound
}
