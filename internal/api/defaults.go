package api

import (
	"os"
	"path/filepath"
	"time"

	"github.com/docker/secrets-engine/pkg/secrets"
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
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "secrets-engine", "engine.sock")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache", "secrets-engine", "engine.sock")
	}
	return filepath.Join(os.TempDir(), "secrets-engine", "engine.sock")
}

func EnvelopeErr(req secrets.Request, err error) secrets.Envelope {
	return secrets.Envelope{ID: req.ID, ResolvedAt: time.Now(), Error: err.Error()}
}
