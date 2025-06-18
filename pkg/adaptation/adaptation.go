package adaptation

import (
	"os"
	"path/filepath"
	"time"
)

const (
	// PluginSocketEnvVar is used to inform plugins about pre-connected sockets.
	PluginSocketEnvVar = "SECRETS_ENGINE_PLUGIN_SOCKET"
	// PluginNameEnvVar is used to inform engine-launched plugins about their name.
	PluginNameEnvVar = "PROVIDER_PLUGIN_NAME"
	// PluginIdxEnvVar is used to inform engine-launched plugins about their ID.
	PluginIdxEnvVar = "PROVIDER_PLUGIN_IDX"
	// PluginRegistrationTimeoutEnvVar is used to inform plugins about the registration timeout.
	// (parsed via time.ParseDuration)
	PluginRegistrationTimeoutEnvVar = "PROVIDER_PLUGIN_REGISTRATION_TIMEOUT"
	// DefaultPluginRegistrationTimeout is the default timeout for plugin registration.
	DefaultPluginRegistrationTimeout = 5 * time.Second
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
