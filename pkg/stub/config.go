package stub

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/docker/secrets-engine/pkg/adaptation"
	"github.com/docker/secrets-engine/pkg/api"
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

// WithPluginIdx sets the index to use in plugin registration.
func WithPluginIdx(idx string) ManualLaunchOption {
	return func(s *cfg) error {
		if err := api.CheckPluginIndex(idx); err != nil {
			return err
		}
		s.idx = idx
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

// WithSocketPath sets the secrets engine socket path to connect to.
func WithSocketPath(path string) ManualLaunchOption {
	return func(s *cfg) error {
		if s.conn != nil {
			return errors.New("cannot set socket path when a connection is already set")
		}
		conn, err := net.Dial("unix", path)
		if err != nil {
			return fmt.Errorf("failed to connect to socket %q: %w", path, err)
		}
		s.conn = conn
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
	plugin Plugin
	identity
	conn                net.Conn
	registrationTimeout time.Duration
}

func newCfg(p Plugin, opts ...ManualLaunchOption) (*cfg, error) {
	if ShouldHaveBeenLaunchedByEngine() {
		logrus.Info("Plugin launched by engine, restoring config...")
		if len(opts) > 0 {
			return nil, errors.New("plugin launched by secrets engine, cannot use manual launch options")
		}
		engineCfg, err := restoreConfig()
		if err != nil {
			return nil, err
		}
		return &cfg{
			plugin:              p,
			identity:            engineCfg.identity,
			conn:                engineCfg.conn,
			registrationTimeout: engineCfg.timeout,
		}, nil
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
	if cfg.idx != "" && cfg.name == "" {
		cfg.name = filepath.Base(os.Args[0])
	}
	if cfg.idx == "" && cfg.name == "" {
		idx, name, err := api.ParsePluginName(filepath.Base(os.Args[0]))
		if err != nil {
			return nil, err
		}
		cfg.idx = idx
		cfg.name = name
	}
	return cfg, nil
}

var (
	errPluginNameNotSet                = errors.New("plugin name not set")
	errPluginIdxNotSet                 = errors.New("plugin index not set")
	errPluginRegistrationTimeoutNotSet = errors.New("plugin registration timeout not set")
	errPluginSocketNotSet              = errors.New("plugin socket fd not set in environment variables")
)

type configFromEngine struct {
	identity identity
	timeout  time.Duration
	conn     net.Conn
}

// Note: Partially set ENV based config as an error, as we expect the
// secret engine to always set all ENV based configuration.
func restoreConfig() (*configFromEngine, error) {
	var (
		name       string
		idx        string
		timeoutStr string
		env        string
	)
	if name = os.Getenv(adaptation.PluginNameEnvVar); name == "" {
		return nil, errPluginNameNotSet
	}
	if idx = os.Getenv(adaptation.PluginIdxEnvVar); idx == "" {
		return nil, errPluginIdxNotSet
	}
	if err := api.CheckPluginIndex(idx); err != nil {
		return nil, fmt.Errorf("invalid plugin index %q: %w", idx, err)
	}
	if timeoutStr = os.Getenv(adaptation.PluginRegistrationTimeoutEnvVar); timeoutStr == "" {
		return nil, errPluginRegistrationTimeoutNotSet
	}
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return nil, fmt.Errorf("invalid registration timeout %q: %w", timeoutStr, err)
	}
	if env = os.Getenv(adaptation.PluginSocketEnvVar); env == "" {
		return nil, errPluginSocketNotSet
	}
	fd, err := strconv.Atoi(env)
	if err != nil {
		return nil, fmt.Errorf("invalid socket fd (%s=%q): %w", adaptation.PluginSocketEnvVar, env, err)
	}
	conn, err := connectionFromFileDescriptor(fd)
	if err != nil {
		return nil, fmt.Errorf("invalid socket (%d) in environment: %w", fd, err)
	}
	return &configFromEngine{
		identity: identity{name: name, idx: idx},
		timeout:  timeout,
		conn:     conn,
	}, nil
}

// ShouldHaveBeenLaunchedByEngine checks if the plugin was launched by the secrets engine.
// Note: There's no 100% guarantee that this really happened, but we take the custom internal
// environment variables as indication that it should have happened.
func ShouldHaveBeenLaunchedByEngine() bool {
	// In theory, all variables should always be set by the engine and we'd just need to check one.
	// But there could be a bug, so we check for any and verify all values are set correctly later.
	name := os.Getenv(adaptation.PluginNameEnvVar)
	idx := os.Getenv(adaptation.PluginIdxEnvVar)
	timeoutStr := os.Getenv(adaptation.PluginRegistrationTimeoutEnvVar)
	env := os.Getenv(adaptation.PluginSocketEnvVar)
	return name != "" || idx != "" || timeoutStr != "" || env != ""
}

type identity struct {
	name string
	idx  string
}

func (i *identity) FullName() string {
	return i.idx + "-" + i.name
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
