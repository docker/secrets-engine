package stub

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/secrets-engine/pkg/adaptation"
	"github.com/docker/secrets-engine/pkg/api"
)

// Option to apply to a plugin during its creation.
type Option func(*cfg) error

// WithPluginName sets the name to use in plugin registration (for manually launched plugins only).
func WithPluginName(name string) Option {
	return func(s *cfg) error {
		if s.name != "" {
			return fmt.Errorf("plugin name already set (%q)", s.name)
		}
		if name == "" {
			return errors.New("plugin name cannot be empty")
		}
		s.name = name
		return nil
	}
}

// WithPluginIdx sets the index to use in plugin registration (for manually launched plugins only).
func WithPluginIdx(idx string) Option {
	return func(s *cfg) error {
		if s.idx != "" {
			return fmt.Errorf("plugin ID already set (%q)", s.idx)
		}
		if err := api.CheckPluginIndex(idx); err != nil {
			return err
		}
		s.idx = idx
		return nil
	}
}

// WithRegistrationTimeout sets custom registration timeout (for manually launched plugins only).
func WithRegistrationTimeout(timeout time.Duration) Option {
	return func(s *cfg) error {
		s.registrationTimeout = timeout
		return nil
	}
}

// WithSocketPath sets the secrets engine socket path to connect to.
func WithSocketPath(path string) Option {
	return func(s *cfg) error {
		s.socketPath = path
		return nil
	}
}

// WithConnection sets an existing secrets engine connection to use.
func WithConnection(conn net.Conn) Option {
	return func(s *cfg) error {
		s.conn = conn
		return nil
	}
}

type cfg struct {
	plugin Plugin
	identity
	socketPath          string
	conn                net.Conn
	registrationTimeout time.Duration
}

func newCfg(p Plugin, opts ...Option) (*cfg, error) {
	identity := &identity{}
	timeout := adaptation.DefaultPluginRegistrationTimeout
	if isPluginEnvSet() {
		var err error
		identity, timeout, err = getCfgFromEnv()
		if err != nil {
			return nil, err
		}
	}
	cfg := &cfg{
		plugin:              p,
		identity:            *identity,
		registrationTimeout: timeout,
		socketPath:          adaptation.DefaultSocketPath,
	}
	for _, o := range opts {
		if err := o(cfg); err != nil {
			return nil, err
		}
	}
	i, err := complementIdentity(cfg.identity)
	if err != nil {
		return nil, err
	}
	cfg.identity = *i
	return cfg, nil
}

var (
	errPluginNameNotSet                = errors.New("plugin name not set")
	errPluginIdxNotSet                 = errors.New("plugin index not set")
	errPluginRegistrationTimeoutNotSet = errors.New("plugin registration timeout not set")
)

// Note: Partially set ENV based config as an error, as we expect the
// secret engine to always set all ENV based configuration.
func getCfgFromEnv() (*identity, time.Duration, error) {
	var (
		name       string
		idx        string
		timeoutStr string
	)
	if name = os.Getenv(adaptation.PluginNameEnvVar); name == "" {
		return nil, 0, errPluginNameNotSet
	}
	if idx = os.Getenv(adaptation.PluginIdxEnvVar); idx == "" {
		return nil, 0, errPluginIdxNotSet
	}
	if err := api.CheckPluginIndex(idx); err != nil {
		return nil, 0, fmt.Errorf("invalid plugin index %q: %w", idx, err)
	}
	if timeoutStr = os.Getenv(adaptation.PluginRegistrationTimeoutEnvVar); timeoutStr == "" {
		return nil, 0, errPluginRegistrationTimeoutNotSet
	}
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid registration timeout %q: %w", timeoutStr, err)
	}
	return &identity{name: name, idx: idx}, timeout, nil
}

func isPluginEnvSet() bool {
	name := os.Getenv(adaptation.PluginNameEnvVar)
	idx := os.Getenv(adaptation.PluginIdxEnvVar)
	timeoutStr := os.Getenv(adaptation.PluginRegistrationTimeoutEnvVar)
	return name != "" || idx != "" || timeoutStr != ""
}

type identity struct {
	name string
	idx  string
}

func (i *identity) FullName() string {
	return i.idx + "-" + i.name
}

func complementIdentity(i identity) (*identity, error) {
	if i.idx != "" && i.name != "" {
		return &i, nil
	}
	if i.idx != "" && i.name == "" {
		i.name = filepath.Base(os.Args[0])
		return &i, nil
	}
	idx, name, err := api.ParsePluginName(filepath.Base(os.Args[0]))
	if err != nil {
		return &i, err
	}
	i.idx = idx
	i.name = name
	return &i, nil
}
