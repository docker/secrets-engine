package engine

import (
	"context"
	"time"

	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

var _ secrets.Resolver = &regResolver{}

type regResolver struct {
	reg    registry
	logger logging.Logger
}

func (r regResolver) GetSecrets(ctx context.Context, req secrets.Request) ([]secrets.Envelope, error) {
	var results []secrets.Envelope

	for _, plugin := range r.reg.GetAll() {
		if req.Provider != "" && req.Provider != plugin.Name().String() {
			continue
		}
		if !plugin.Pattern().Includes(req.Pattern) {
			continue
		}

		envelopes, err := plugin.GetSecrets(ctx, req)
		if err != nil {
			r.logger.Errorf("plugin '%s': %s", plugin.Name(), err)
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

	return results, secrets.ErrNotFound
}
