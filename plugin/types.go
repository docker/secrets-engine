package plugin

import (
	"context"
	"time"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/plugins"
	"github.com/docker/secrets-engine/x/secrets"
)

type (
	Resolver = secrets.Resolver
	Envelope = secrets.Envelope

	Version = api.Version
	ID      = secrets.ID
	Pattern = secrets.Pattern
	Logger  = logging.Logger
	// Plugin is an internal engine plugin
	Plugin = plugins.Plugin
)

var ErrNotFound = secrets.ErrNotFound

type ExternalPlugin interface {
	Resolver
}

// Stub is the interface the stub provides for the plugin implementation.
type Stub interface {
	// Run starts the plugin then waits for the plugin service to exit, either due to a
	// critical error or by cancelling the context. Calling Run() while the plugin is running,
	// will result in an error. After the plugin service exits, Run() can safely be called again.
	Run(context.Context) error

	// RegistrationTimeout returns the registration timeout for the stub.
	// This is the default timeout if the plugin has not been started or
	// the timeout received in the Configure request otherwise.
	RegistrationTimeout() time.Duration

	// RequestTimeout returns the request timeout for the stub.
	// This is the default timeout if the plugin has not been started or
	// the timeout received in the Configure request otherwise.
	RequestTimeout() time.Duration
}

type Config struct {
	// Version of the plugin in semver format.
	Version Version
	// Pattern to control which IDs should match this plugin. Set to `**` to match any ID.
	Pattern Pattern
	// Logger to be used within plugin side SDK code. If nil, a default logger will be created and used.
	Logger Logger
}
