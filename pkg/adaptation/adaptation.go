package adaptation

import "time"

const (
	// DefaultSocketPath is the default socket path for external plugins.
	DefaultSocketPath = "/var/run/secrets-engine/engine.sock"
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
