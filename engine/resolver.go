package engine

import (
	"context"
	"errors"
	"time"

	"github.com/docker/secrets-engine/engine/internal/config"
	"github.com/docker/secrets-engine/x/secrets"
)

var _ secrets.Resolver = &regResolver{}

type regResolver struct {
	reg registry
	cfg config.Engine
}

func newRegResolver(cfg config.Engine, reg registry) *regResolver {
	return &regResolver{
		cfg: cfg,
		reg: reg,
	}
}

func (r regResolver) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	var results []secrets.Envelope

	for plugin := range r.reg.Iterator() {
		if !plugin.Pattern().Includes(pattern) {
			continue
		}

		envelopes, err := plugin.GetSecrets(ctx, pattern)
		if err != nil {
			if !errors.Is(err, secrets.ErrNotFound) {
				r.cfg.Logger().Errorf("plugin '%s': %s", plugin.Name(), err)
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

	r.cfg.Tracker().TrackEvent(EventSecretsEngineRequest{ResultsTotal: len(results)})

	if len(results) > 0 {
		return results, nil
	}

	return results, secrets.ErrNotFound
}

type EventSecretsEngineRequest struct {
	ResultsTotal int `json:"results_total"`
}
