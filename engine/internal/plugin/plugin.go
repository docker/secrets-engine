package plugin

import (
	"context"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

type Plugin interface {
	secrets.Resolver

	Run(ctx context.Context) error
}

type Metadata interface {
	Name() api.Name
	Version() api.Version
	Pattern() secrets.Pattern
}
