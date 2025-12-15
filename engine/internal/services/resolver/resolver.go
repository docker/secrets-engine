package resolver

import (
	"context"
	"errors"
	"time"

	"github.com/docker/secrets-engine/engine/internal/registry"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/telemetry"
)

type Service interface {
	secrets.Resolver
}

var _ Service = &resolver{}

type resolver struct {
	reg     registry.Registry
	logger  logging.Logger
	tracker telemetry.Tracker
}

func NewService(logger logging.Logger, tracker telemetry.Tracker, reg registry.Registry) Service {
	return &resolver{
		reg:     reg,
		logger:  logger,
		tracker: tracker,
	}
}

func (r resolver) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	var results []secrets.Envelope

	for plugin := range r.reg.Iterator() {
		filteredPattern, ok := secrets.Filter(plugin.Pattern(), pattern)
		if !ok {
			continue
		}

		envelopes, err := plugin.GetSecrets(ctx, filteredPattern)
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

	r.tracker.TrackEvent(EventSecretsEngineRequest{ResultsTotal: len(results)})

	if len(results) > 0 {
		return results, nil
	}

	return results, secrets.ErrNotFound
}

type EventSecretsEngineRequest struct {
	ResultsTotal int `json:"results_total"`
}
