package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/docker/secrets-engine/internal/api"
	"github.com/docker/secrets-engine/plugin"
)

const (
	// DefaultPluginPath is the default path to search for secrets engine plugins.
	DefaultPluginPath = "/opt/docker/secrets-engine/plugins"
)

type Engine interface {
	Start() error
	Stop() error
}

type Plugin interface {
	plugin.Plugin

	Run(ctx context.Context) error
}

type config struct {
	name       string
	version    string
	pluginPath string
	socketPath string
}

type adaptation struct {
	config

	m sync.Mutex
	e io.Closer
}

// Option to apply to the secrets engine.
type Option func(*config) error

// WithPluginPath returns an option to override the default plugin path.
func WithPluginPath(path string) Option {
	return func(r *config) error {
		r.pluginPath = path
		return nil
	}
}

// WithSocketPath returns an option to override the default socket path.
func WithSocketPath(path string) Option {
	return func(r *config) error {
		r.socketPath = path
		return nil
	}
}

// New creates a new NRI Runtime.
func New(name, version string, opts ...Option) (Engine, error) {
	cfg := &config{
		name:       name,
		version:    version,
		pluginPath: DefaultPluginPath,
		socketPath: api.DefaultSocketPath(),
	}

	for _, o := range opts {
		if err := o(cfg); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return &adaptation{config: *cfg}, nil
}

func (a *adaptation) Start() error {
	a.m.Lock()
	defer a.m.Unlock()
	if a.e != nil {
		return errors.New("already started")
	}
	logrus.Infof("secrets engine starting up...")
	e, err := newEngine(a.config)
	if err != nil {
		return err
	}
	a.e = e
	return nil
}

func (a *adaptation) Stop() error {
	a.m.Lock()
	defer a.m.Unlock()
	if a.e == nil {
		return nil
	}
	logrus.Infof("secrets engine shutting down...")
	err := a.e.Close()
	a.e = nil
	return err
}

func toDisplayName(filename string) string {
	return strings.TrimSuffix(filename, ".exe")
}
