package engine

import (
	"context"
	"errors"
	"time"

	"github.com/docker/secrets-engine/x/secrets"
)

var _ secrets.Resolver = &regResolver{}

type regResolver struct {
	reg registry
}

func (r regResolver) GetSecrets(ctx context.Context, req secrets.Request) ([]secrets.Envelope, error) {
	var errs []error
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
			// TODO: log the error
			errs = append(errs, err)
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

	if len(results) == 0 && len(errs) == 0 {
		return secrets.EnvelopeErrs(secrets.ErrNotFound), secrets.ErrNotFound
	}

	return results, errors.Join(errs...)
}
