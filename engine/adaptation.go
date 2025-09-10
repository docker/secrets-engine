package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/docker/secrets-engine/plugin"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/oshelper"
	"github.com/docker/secrets-engine/x/secrets"
)

type (
	Version = api.Version
	Logger  = logging.Logger
)

var (
	NewVersion       = api.NewVersion
	MustNewVersion   = api.MustNewVersion
	NewDefaultLogger = logging.NewDefaultLogger

	NotifyContext = oshelper.NotifyContext
)

const (
	// DefaultPluginPath is the default path to search for secrets engine plugins.
	DefaultPluginPath = "/opt/docker/secrets-engine/plugins"
)

type Plugin interface {
	plugin.Plugin

	Run(ctx context.Context) error
}

type Config struct {
	Name string
	// Version of the plugin in semver format.
	Version api.Version
	// Pattern to control which IDs should match this plugin. Set to `**` to match any ID.
	Pattern secrets.Pattern
}

func (c *Config) validated() (metadata, error) {
	name, err := api.NewName(c.Name)
	if err != nil {
		return nil, err
	}
	if c.Version == nil {
		return nil, errors.New("version is required")
	}
	if c.Pattern == nil {
		return nil, errors.New("pattern is required")
	}
	return &configValidated{name, c.Version, c.Pattern}, nil
}

type config struct {
	name                   string
	version                string
	pluginPath             string
	socketPath             string
	plugins                map[metadata]Plugin
	dynamicPluginsDisabled bool
	enginePluginsDisabled  bool
	logger                 logging.Logger
	maxTries               uint
	upCb                   func(ctx context.Context) error
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
func WithPlugins(plugins map[Config]Plugin) Option {
	return func(r *config) error {
		pluginsValidated := map[metadata]Plugin{}
		for unvalidated, p := range plugins {
			c, err := unvalidated.validated()
			if err != nil {
				return err
			}
			pluginsValidated[c] = p
		}
		r.plugins = pluginsValidated
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

// WithMaxTries limits the number of all attempts.
// Unlimited by default (maxTries == 0).
func WithMaxTries(maxTries uint) Option {
	return func(r *config) error {
		r.maxTries = maxTries
		return nil
	}
}

// WithAfterHealthyHook set a callback that gets called once the engine is ready to accept requests.
func WithAfterHealthyHook(cb func(ctx context.Context) error) Option {
	return func(r *config) error {
		r.upCb = cb
		return nil
	}
}

func Run(ctx context.Context, name, version string, opts ...Option) error {
	cfg := &config{
		name:       name,
		version:    version,
		pluginPath: DefaultPluginPath,
		socketPath: api.DefaultSocketPath(),
	}

	for _, o := range opts {
		if err := o(cfg); err != nil {
			return fmt.Errorf("failed to apply option: %w", err)
		}
	}
	if cfg.logger == nil {
		cfg.logger = logging.NewDefaultLogger("engine")
	}

	cfg.logger.Printf("secrets engine starting up... (%s)", tryMaskHomePath(cfg.socketPath))
	e, err := newEngine(logging.WithLogger(ctx, cfg.logger), *cfg)
	if err != nil {
		return err
	}
	cfg.logger.Printf("secrets engine ready")
	if cfg.upCb != nil {
		if err := cfg.upCb(ctx); err != nil {
			e.Close()
			return err
		}
	}
	<-ctx.Done()
	cfg.logger.Printf("secrets engine shutting down...")
	return e.Close()
}

func toDisplayName(filename string) string {
	return strings.TrimSuffix(filename, ".exe")
}

func tryMaskHomePath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return strings.Replace(path, home, "~", 1)
}
