package engine

import (
	"context"
	"errors"
	"time"

	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

var _ secrets.Resolver = &regResolver{}

type regResolver struct {
	reg    registry
	logger logging.Logger
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

	return results, secrets.ErrNotFound
}
