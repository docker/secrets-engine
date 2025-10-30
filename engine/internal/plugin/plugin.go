package plugin

import (
	"context"
	"io"

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

type Runtime interface {
	secrets.Resolver

	io.Closer

	Metadata

	Closed() <-chan struct{}
}

type ExternalRuntime interface {
	Runtime
	Watcher() Watcher
}
