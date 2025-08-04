package api

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/secrets-engine/internal/secrets"
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

type PluginDataUnvalidated struct {
	Name    string
	Version string
	Pattern string
}

func MustNewPluginData(in PluginDataUnvalidated) PluginData {
	data, err := NewPluginData(in)
	if err != nil {
		panic(err)
	}
	return data
}

func NewPluginData(in PluginDataUnvalidated) (PluginData, error) {
	if in.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if in.Version == "" {
		return nil, fmt.Errorf("version is required")
	}
	pattern, err := secrets.ParsePattern(in.Pattern)
	if err != nil {
		return nil, err
	}
	return &pluginData{
		name:    in.Name,
		version: in.Version,
		pattern: pattern,
	}, nil
}

type pluginData struct {
	name    string
	version string
	pattern secrets.Pattern
}

func (p pluginData) Name() string {
	return p.name
}

func (p pluginData) Pattern() secrets.Pattern {
	return p.pattern
}

func (p pluginData) Version() string {
	return p.version
}

type PluginData interface {
	Name() string
	Pattern() secrets.Pattern
	Version() string
}
