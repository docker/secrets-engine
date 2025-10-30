package config

import (
	"net"

	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/telemetry"
)

type Engine interface {
	Name() string
	Version() string
	Listener() net.Listener
	PluginPath() string
	Logger() logging.Logger
	Tracker() telemetry.Tracker
	DynamicPluginsEnabled() bool
	PluginLaunchMaxRetries() uint
	LaunchedPluginsEnabled() bool
	Plugins() map[plugin.Metadata]plugin.Plugin
}
