package api

import (
	"os"
	"path/filepath"
	"time"
)

const (
	// PluginLaunchedByEngineVar is used to inform engine-launched plugins about their name.
	PluginLaunchedByEngineVar = "DOCKER_SECRETS_ENGINE_PLUGIN_LAUNCH_CFG"
	// DefaultPluginRegistrationTimeout is the default timeout for plugin registration.
	DefaultPluginRegistrationTimeout = 5 * time.Second
	// DefaultPluginRequestTimeout is the default timeout for plugins to handle a request.
	DefaultPluginRequestTimeout = 2 * time.Second
)

func DefaultSocketPath() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "docker-secrets-engine", "engine.sock")
	}
	return filepath.Join(os.TempDir(), "docker-secrets-engine", "engine.sock")
}
