package plugin

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/secrets-engine/internal/api"
	"github.com/docker/secrets-engine/internal/ipc"
)

const hijackTimeout = 2 * time.Second

// ManualLaunchOption to apply to a plugin during its creation
// when it's manually launched (not by the secrets engine).
type ManualLaunchOption func(c *cfg) error

// WithPluginName sets the name to use in plugin registration.
func WithPluginName(name string) ManualLaunchOption {
	return func(s *cfg) error {
		if name == "" {
			return errors.New("plugin name cannot be empty")
		}
		s.name = name
		return nil
	}
}

// WithRegistrationTimeout sets custom registration timeout.
func WithRegistrationTimeout(timeout time.Duration) ManualLaunchOption {
	return func(s *cfg) error {
		s.registrationTimeout = timeout
		return nil
	}
}

// WithConnection sets an existing secrets engine connection to use.
func WithConnection(conn net.Conn) ManualLaunchOption {
	return func(s *cfg) error {
		if s.conn != nil {
			return errors.New("connection already set")
		}
		hijackedConn, err := ipc.Hijackify(conn, hijackTimeout)
		if err != nil {
			return fmt.Errorf("external plugin rejected: %w", err)
		}
		s.conn = hijackedConn
		return nil
	}
}

type cfg struct {
	plugin              Plugin
	name                string
	conn                io.ReadWriteCloser
	registrationTimeout time.Duration
}

func newCfg(p Plugin, opts ...ManualLaunchOption) (*cfg, error) {
	engineCfg, err := restoreConfig(p)
	if errors.Is(err, errPluginNotLaunchedByEngine) {
		return newCfgForManualLaunch(p, opts...)
	}
	return engineCfg, err
}

func newCfgForManualLaunch(p Plugin, opts ...ManualLaunchOption) (*cfg, error) {
	cfg := &cfg{
		plugin:              p,
		registrationTimeout: api.DefaultPluginRegistrationTimeout,
	}
	for _, o := range opts {
		if err := o(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.conn == nil {
		defaultSocketPath := api.DefaultSocketPath()
		conn, err := net.Dial("unix", defaultSocketPath)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to default socket %q: %w", defaultSocketPath, err)
		}
		hijackedConn, err := ipc.Hijackify(conn, hijackTimeout)
		if err != nil {
			return nil, fmt.Errorf("external plugin rejected: %w", err)
		}
		cfg.conn = hijackedConn
	}
	if cfg.name == "" {
		if len(os.Args) == 0 {
			// This should never happen in practice but can happen in tests or when something else empties os.Args for whatever reason.
			return nil, errors.New("plugin name must be specified (could not derive from os.Args)")
		}
		cfg.name = filepath.Base(os.Args[0])
	}
	return cfg, nil
}

var errPluginNotLaunchedByEngine = errors.New("plugin not launched by secrets engine")

func restoreConfig(p Plugin) (*cfg, error) {
	cfgString := os.Getenv(api.PluginLaunchedByEngineVar)
	if cfgString == "" {
		return nil, errPluginNotLaunchedByEngine
	}
	c, err := ipc.NewPluginConfigFromEngineEnv(cfgString)
	if err != nil {
		return nil, err
	}
	conn, err := ipc.FromCustomCfg(c.Custom)
	if err != nil {
		return nil, err
	}
	return &cfg{
		plugin:              p,
		name:                c.Name,
		conn:                conn,
		registrationTimeout: c.RegistrationTimeout,
	}, nil
}
