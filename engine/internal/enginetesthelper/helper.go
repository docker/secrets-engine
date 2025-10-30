package enginetesthelper

import (
	"net"
	"testing"

	"github.com/docker/secrets-engine/engine/internal/config"
	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/telemetry"
	"github.com/docker/secrets-engine/x/testhelper"
)

type TestEngineConfig struct {
	T                          *testing.T
	TestName                   string
	TestVersion                string
	TestPluginPath             string
	TestPluginLaunchMaxRetries uint
	TestDynamicPluginsEnabled  bool
	TestListener               net.Listener
	TestPluginsDisabled        bool
	TestPlugins                map[plugin.Metadata]plugin.Plugin
	TestTracker                telemetry.Tracker
}

func (t *TestEngineConfig) Plugins() map[plugin.Metadata]plugin.Plugin {
	return t.TestPlugins
}

func (t *TestEngineConfig) LaunchedPluginsEnabled() bool {
	return !t.TestPluginsDisabled
}

func (t *TestEngineConfig) Listener() net.Listener {
	return t.TestListener
}

func (t *TestEngineConfig) DynamicPluginsEnabled() bool {
	return t.TestDynamicPluginsEnabled
}

func (t *TestEngineConfig) Logger() logging.Logger {
	return testhelper.TestLogger(t.T)
}

func (t *TestEngineConfig) Name() string {
	return t.TestName
}

func (t *TestEngineConfig) PluginLaunchMaxRetries() uint {
	return t.TestPluginLaunchMaxRetries
}

func (t *TestEngineConfig) PluginPath() string {
	return t.TestPluginPath
}

func (t *TestEngineConfig) Tracker() telemetry.Tracker {
	if t.TestTracker == nil {
		return telemetry.NoopTracker()
	}
	return t.TestTracker
}

func (t *TestEngineConfig) Version() string {
	return t.TestVersion
}

var _ config.Engine = &TestEngineConfig{}
