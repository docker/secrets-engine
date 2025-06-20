package adaptation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// PluginLaunchedByEngineVar is used to inform engine-launched plugins about their name.
	PluginLaunchedByEngineVar = "DOCKER_SECRETS_ENGINE_PLUGIN_LAUNCH_CFG"
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

type PluginConfigFromEngine struct {
	Name                string        `json:"name"`
	RegistrationTimeout time.Duration `json:"timeout"`
	Fd                  int           `json:"fd"`
}

func (c *PluginConfigFromEngine) ToString() (string, error) {
	result, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func NewPluginConfigFromEngineEnv(in string) (*PluginConfigFromEngine, error) {
	var result PluginConfigFromEngine
	if err := json.Unmarshal([]byte(in), &result); err != nil {
		return nil, fmt.Errorf("failed to decode plugin config from engine %q: %w", PluginLaunchedByEngineVar, err)
	}
	if result.Name == "" {
		return nil, errors.New("plugin name is required")
	}
	if result.RegistrationTimeout == 0 {
		return nil, errors.New("plugin registration timeout is required")
	}
	if result.Fd <= 2 {
		// File descriptors 0, 1, and 2 are reserved for stdin, stdout, and stderr.
		return nil, errors.New("invalid file descriptor for plugin connection")
	}
	return &result, nil
}
