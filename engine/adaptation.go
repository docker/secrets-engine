package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/docker/secrets-engine/internal/api"
	"github.com/docker/secrets-engine/internal/logging"
	"github.com/docker/secrets-engine/plugin"
)

const (
	// DefaultPluginPath is the default path to search for secrets engine plugins.
	DefaultPluginPath = "/opt/docker/secrets-engine/plugins"
)

type Engine interface {
	// Run the engine. Calling Cancel() on the context will stop the engine.
	// Optionally pass in callbacks that get called once the engine is ready to accept requests.
	Run(ctx context.Context, up ...func()) error
}

type Plugin interface {
	plugin.Plugin

	Run(ctx context.Context) error
}

type config struct {
	name                   string
	version                string
	pluginPath             string
	socketPath             string
	plugins                map[string]Plugin
	dynamicPluginsDisabled bool
	enginePluginsDisabled  bool
	logger                 logging.Logger
}

type adaptation struct {
	config

	m sync.Mutex
}

// Option to apply to the secrets engine.
type Option func(*config) error

// WithPluginPath returns an option to override the default plugin path.
func WithPluginPath(path string) Option {
	return func(r *config) error {
		r.pluginPath = path
		return nil
	}
}

// WithSocketPath returns an option to override the default socket path.
func WithSocketPath(path string) Option {
	return func(r *config) error {
		r.socketPath = path
		return nil
	}
}

// WithPlugins sets a list of plugins that get bundled with the engine (batteries included plugins)
func WithPlugins(plugins map[string]Plugin) Option {
	return func(r *config) error {
		r.plugins = plugins
		return nil
	}
}

// WithExternallyLaunchedPluginsDisabled disables accepting plugin registration requests coming
// from plugins that have been launched externally
func WithExternallyLaunchedPluginsDisabled() Option {
	return func(r *config) error {
		r.dynamicPluginsDisabled = true
		return nil
	}
}

// WithEngineLaunchedPluginsDisabled disables launching any plugins from the plugin directory
func WithEngineLaunchedPluginsDisabled() Option {
	return func(r *config) error {
		r.enginePluginsDisabled = true
		return nil
	}
}

func WithLogger(logger logging.Logger) Option {
	return func(r *config) error {
		r.logger = logger
		return nil
	}
}

// New creates a new NRI Runtime.
func New(name, version string, opts ...Option) (Engine, error) {
	cfg := &config{
		name:       name,
		version:    version,
		pluginPath: DefaultPluginPath,
		socketPath: api.DefaultSocketPath(),
	}

	for _, o := range opts {
		if err := o(cfg); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	if cfg.logger == nil {
		cfg.logger = logging.NewDefaultLogger("engine")
	}

	return &adaptation{config: *cfg}, nil
}

func (a *adaptation) Run(ctx context.Context, up ...func()) error {
	if !a.m.TryLock() {
		return errors.New("already started")
	}
	defer a.m.Unlock()
	a.logger.Printf("secrets engine starting up...")
	e, err := newEngine(logging.WithLogger(ctx, a.logger), a.config)
	if err != nil {
		return err
	}
	a.logger.Printf("secrets engine ready")
	for _, cb := range up {
		go cb()
	}
	<-ctx.Done()
	a.logger.Printf("secrets engine shutting down...")
	return e.Close()
}

func toDisplayName(filename string) string {
	return strings.TrimSuffix(filename, ".exe")
}
