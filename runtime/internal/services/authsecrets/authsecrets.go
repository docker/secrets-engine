package authsecrets

import (
	"context"

	"github.com/docker/secrets-engine/runtime/internal/registry"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/telemetry"
)

func New() Service {
	return &authService{}
}

type Service interface {
	Save(ctx context.Context, id secrets.ID, secret secrets.Envelope) error
	Delete(ctx context.Context, id secrets.ID) error
	Get(ctx context.Context, id secrets.ID) (secrets.Envelope, error)
}

type authService struct {
	reg     registry.Registry
	logger  logging.Logger
	tracker telemetry.Tracker
}
