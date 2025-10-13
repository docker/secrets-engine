package engine

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/oshelper"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/telemetry"
)

type (
	Resolver = secrets.Resolver
	Envelope = secrets.Envelope

	Version = api.Version
	ID      = secrets.ID
	Pattern = secrets.Pattern
	Logger  = logging.Logger

	Tracker = telemetry.Tracker
)

var (
	ParseID          = secrets.ParseID
	MustParseID      = secrets.MustParseID
	ParsePattern     = secrets.ParsePattern
	MustParsePattern = secrets.MustParsePattern
	NewVersion       = api.NewVersion
	MustNewVersion   = api.MustNewVersion
	NewDefaultLogger = logging.NewDefaultLogger

	NotifyContext     = oshelper.NotifyContext
	DefaultSocketPath = api.DefaultSocketPath

	ErrSecretNotFound = secrets.ErrNotFound
)

const (
	// DefaultPluginPath is the default path to search for secrets engine plugins.
	DefaultPluginPath = "/opt/docker/secrets-engine/plugins"
)

type Plugin interface {
	Resolver

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
	listener               net.Listener
	plugins                map[metadata]Plugin
	dynamicPluginsDisabled bool
	enginePluginsDisabled  bool
	logger                 logging.Logger
	maxTries               uint
	upCb                   func(ctx context.Context) error
	tracker                telemetry.Tracker
	certPool               *x509.CertPool
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
		if r.listener != nil {
			return errors.New("listener already set")
		}
		listener, err := createListener(path)
		if err != nil {
			return err
		}
		r.listener = listener
		return nil
	}
}

// WithListener sets the listener (and thereby overwrites using the default socket path)
func WithListener(listener net.Listener) Option {
	return func(r *config) error {
		if r.listener != nil {
			return errors.New("listener already set")
		}
		r.listener = listener
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

// WithTracker set a tracker (default: noop tracker)
func WithTracker(tracker telemetry.Tracker) Option {
	return func(r *config) error {
		r.tracker = telemetry.AsyncWrapper(tracker)
		return nil
	}
}

func Run(ctx context.Context, name, version string, opts ...Option) error {
	cfg := &config{
		name:       name,
		version:    version,
		pluginPath: DefaultPluginPath,
	}

	for _, o := range opts {
		if err := o(cfg); err != nil {
			return fmt.Errorf("failed to apply option: %w", err)
		}
	}
	if cfg.tracker == nil {
		cfg.tracker = telemetry.NoopTracker()
	}
	if cfg.logger == nil {
		cfg.logger = logging.NewDefaultLogger("engine")
	}
	ctx = logging.WithLogger(ctx, cfg.logger)
	cfg.tracker.TrackEvent(EventSecretsEngineStarted{})
	var span trace.Span
	ctx, span = tracer().Start(ctx, "engine.run",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("service.name", cfg.name),
			attribute.String("service.version", cfg.version),
		))
	defer span.End()

	var socketInfo string
	if cfg.listener == nil {
		listener, err := createListener(api.DefaultSocketPath())
		if err != nil {
			recordErrorWithStatus(cfg.tracker, span, err, "create_listener", "create_failure")
			return err
		}
		cfg.listener = listener
		socketInfo = " (" + tryMaskHomePath(api.DefaultSocketPath()) + ")"
	}

	cfg.logger.Printf("secrets engine starting up..." + socketInfo)
	e, err := newEngine(ctx, *cfg)
	if err != nil {
		recordErrorWithStatus(cfg.tracker, span, err, "create_engine", "init_failure")
		return err
	}
	span.AddEvent("ready")
	cfg.logger.Printf("secrets engine ready")
	if cfg.upCb != nil {
		if err := cfg.upCb(ctx); err != nil {
			e.Close()
			recordErrorWithStatus(cfg.tracker, span, err, "up_callback", "callback_failure")
			return err
		}
	}
	<-ctx.Done()
	span.AddEvent("shutdown")
	cfg.logger.Printf("secrets engine shutting down...")
	if err := e.Close(); err != nil {
		recordErrorWithStatus(cfg.tracker, span, err, "shutdown", "shutdown_failure")
		return err
	}
	span.SetStatus(codes.Ok, "clean shutdown")
	return nil
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

func recordErrorWithStatus(tracker telemetry.Tracker, span trace.Span, err error, phase, status string) {
	tracker.Notify(err, phase, status)
	span.SetStatus(codes.Error, status)
	span.RecordError(err, trace.WithAttributes(attribute.String("phase", phase)))
}

type EventSecretsEngineStarted struct{}
