package stub

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/docker/secrets-engine/pkg/adaptation"
)

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
		s.conn = conn
		return nil
	}
}

type cfg struct {
	plugin              Plugin
	name                string
	conn                net.Conn
	registrationTimeout time.Duration
}

func newCfg(p Plugin, opts ...ManualLaunchOption) (*cfg, error) {
	engineCfg, err := restoreConfig(p)
	if err != nil && !errors.Is(err, errPluginNotLaunchedByEngine) {
		return nil, err
	}
	if err == nil && engineCfg != nil {
		return engineCfg, nil
	}
	return newCfgForManualLaunch(p, opts...)
}

func newCfgForManualLaunch(p Plugin, opts ...ManualLaunchOption) (*cfg, error) {
	cfg := &cfg{
		plugin:              p,
		registrationTimeout: adaptation.DefaultPluginRegistrationTimeout,
	}
	for _, o := range opts {
		if err := o(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.conn == nil {
		defaultSocketPath := adaptation.DefaultSocketPath()
		conn, err := net.Dial("unix", defaultSocketPath)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to default socket %q: %w", defaultSocketPath, err)
		}
		cfg.conn = conn
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

var (
	errPluginNotLaunchedByEngine = errors.New("plugin not launched by secrets engine")
)

func restoreConfig(p Plugin) (*cfg, error) {
	cfgString := os.Getenv(adaptation.PluginLaunchedByEngineVar)
	if cfgString == "" {
		return nil, errPluginNotLaunchedByEngine
	}
	c, err := adaptation.NewPluginConfigFromEngineFromString(cfgString)
	if err != nil {
		return nil, err
	}
	conn, err := connectionFromFileDescriptor(c.Fd)
	if err != nil {
		return nil, fmt.Errorf("invalid socket (%d) in environment: %w", c.Fd, err)
	}
	return &cfg{
		plugin:              p,
		name:                c.Name,
		conn:                conn,
		registrationTimeout: c.RegistrationTimeout,
	}, nil
}

func connectionFromFileDescriptor(fd int) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), "fd #"+strconv.Itoa(fd))
	if f == nil {
		return nil, fmt.Errorf("failed to open FD %d", fd)
	}
	defer f.Close()
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create net.Conn for fd #%d: %w", fd, err)
	}
	return conn, nil
}
