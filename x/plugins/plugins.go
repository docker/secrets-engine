package plugins

import (
	"context"

	"github.com/docker/secrets-engine/x/secrets"
)

type Plugin interface {
	secrets.Resolver

	Run(ctx context.Context) error
}
