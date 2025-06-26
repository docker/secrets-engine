package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/docker/secrets-engine/pkg/api"
)

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
		return nil, fmt.Errorf("failed to decode plugin config from engine %q: %w", api.PluginLaunchedByEngineVar, err)
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
