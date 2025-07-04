package adaptation

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/docker/secrets-engine/pkg/api"
)

const (
	// DefaultPluginPath is the default path to search for secrets engine plugins.
	DefaultPluginPath = "/opt/docker/secrets-engine/plugins"
)

type Engine interface {
	Start() error
	Stop()
}

type adaptation struct {
	name       string
	version    string
	pluginPath string
	socketPath string
}

// Option to apply to the secrets engine.
type Option func(*adaptation) error

// WithPluginPath returns an option to override the default plugin path.
func WithPluginPath(path string) Option {
	return func(r *adaptation) error {
		r.pluginPath = path
		return nil
	}
}

// WithSocketPath returns an option to override the default socket path.
func WithSocketPath(path string) Option {
	return func(r *adaptation) error {
		r.socketPath = path
		return nil
	}
}

// New creates a new NRI Runtime.
func New(name, version string, opts ...Option) (Engine, error) {
	r := &adaptation{
		name:       name,
		version:    version,
		pluginPath: DefaultPluginPath,
		socketPath: api.DefaultSocketPath(),
	}

	for _, o := range opts {
		if err := o(r); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return r, nil
}

func (r *adaptation) Start() error {
	logrus.Infof("secrets engine starting up...")
	return nil
}

func (r *adaptation) Stop() {
	logrus.Infof("secrets engine shutting down...")
}
