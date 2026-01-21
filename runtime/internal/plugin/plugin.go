package plugin

import (
	"io"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/plugins"
	"github.com/docker/secrets-engine/x/secrets"
)

type Plugin = plugins.Plugin

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

type RegistrationResult struct {
	Config Metadata
	Err    error
}
