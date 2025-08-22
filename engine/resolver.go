package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docker/secrets-engine/x/secrets"
)

var _ secrets.Resolver = &regResolver{}

type regResolver struct {
	reg registry
}

func (r regResolver) GetSecret(ctx context.Context, req secrets.Request) (secrets.Envelope, error) {
	var errs []error

	for _, plugin := range r.reg.GetAll() {
		if req.Provider != "" && req.Provider != plugin.Name().String() {
			continue
		}
		if !plugin.Pattern().Match(req.ID) {
			continue
		}

		envelope, err := plugin.GetSecret(ctx, req)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// we use the first matching, successful registration to resolve the secret.
		envelope.Provider = plugin.Name().String()

		if envelope.ResolvedAt.IsZero() {
			envelope.ResolvedAt = time.Now().UTC()
		}
		return envelope, nil
	}

	var err error
	if len(errs) == 0 {
		err = fmt.Errorf("secret %q: %w", req.ID, secrets.ErrNotFound)
	} else {
		err = errors.Join(errs...)
	}
	return secrets.EnvelopeErr(req, err), err
}
