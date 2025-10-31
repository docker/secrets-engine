package testhelper

import (
	"net"
	"testing"

	"github.com/docker/secrets-engine/engine/internal/config"
	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/telemetry"
	"github.com/docker/secrets-engine/x/testhelper"
)

type testEngineConfig struct {
	t                      *testing.T
	name                   string
	version                string
	pluginPath             string
	pluginLaunchMaxRetries uint
	dynamicPluginsDisabled bool
	listener               net.Listener
	pluginsDisabled        bool
	plugins                map[plugin.Metadata]plugin.Plugin
	tracker                telemetry.Tracker
	logger                 logging.Logger
}

type Options func(*testEngineConfig)

func WithName(name string) Options {
	return func(tec *testEngineConfig) {
		tec.name = name
	}
}

func WithVersion(version string) Options {
	return func(tec *testEngineConfig) {
		tec.version = version
	}
}

func WithPluginPath(path string) Options {
	return func(tec *testEngineConfig) {
		tec.pluginPath = path
	}
}

func WithPluginLaunchMaxRetries(retries uint) Options {
	return func(tec *testEngineConfig) {
		tec.pluginLaunchMaxRetries = retries
	}
}

func WithDisableDynamicPlugins() Options {
	return func(tec *testEngineConfig) {
		tec.dynamicPluginsDisabled = true
	}
}

func WithListener(listener net.Listener) Options {
	return func(tec *testEngineConfig) {
		tec.listener = listener
	}
}

func WithPluginsDisabled(disable bool) Options {
	return func(tec *testEngineConfig) {
		tec.pluginsDisabled = disable
	}
}

func WithPlugins(plugins map[plugin.Metadata]plugin.Plugin) Options {
	return func(tec *testEngineConfig) {
		tec.plugins = plugins
	}
}

func WithTracker(tracker telemetry.Tracker) Options {
	return func(tec *testEngineConfig) {
		tec.tracker = tracker
	}
}

func NewEngineConfig(t *testing.T, opts ...Options) config.Engine {
	c := &testEngineConfig{
		t:       t,
		logger:  testhelper.TestLogger(t),
		tracker: telemetry.NoopTracker(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (t *testEngineConfig) Plugins() map[plugin.Metadata]plugin.Plugin {
	return t.plugins
}

func (t *testEngineConfig) LaunchedPluginsEnabled() bool {
	return !t.pluginsDisabled
}

func (t *testEngineConfig) Listener() net.Listener {
	return t.listener
}

func (t *testEngineConfig) DynamicPluginsEnabled() bool {
	return !t.dynamicPluginsDisabled
}

func (t *testEngineConfig) Logger() logging.Logger {
	return t.logger
}

func (t *testEngineConfig) Name() string {
	return t.name
}

func (t *testEngineConfig) PluginLaunchMaxRetries() uint {
	return t.pluginLaunchMaxRetries
}

func (t *testEngineConfig) PluginPath() string {
	return t.pluginPath
}

func (t *testEngineConfig) Tracker() telemetry.Tracker {
	if t.tracker == nil {
		return telemetry.NoopTracker()
	}
	return t.tracker
}

func (t *testEngineConfig) Version() string {
	return t.version
}

var _ config.Engine = &testEngineConfig{}
