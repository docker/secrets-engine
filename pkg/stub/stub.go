package stub

import (
	"context"

	"github.com/docker/secrets-engine/pkg/secrets"
)

type Plugin interface {
	secrets.Resolver

	Shutdown(context.Context)
}
