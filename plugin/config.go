// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/ipc"
)

const hijackTimeout = 2 * time.Second

// ManualLaunchOption to apply to a plugin during its creation
// when it's manually launched (not by the secrets runtime).
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

// WithConnection sets an existing secrets runtime connection to use.
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
	Config
	plugin              ExternalPlugin
	name                string
	conn                io.ReadWriteCloser
	registrationTimeout time.Duration
}

func newCfg(p ExternalPlugin, opts ...ManualLaunchOption) (*cfg, error) {
	engineCfg, err := restoreConfig(p)
	if errors.Is(err, errPluginNotLaunchedByEngine) {
		cfg, err := newCfgForManualLaunch(p, opts...)
		return cfg, err
	}
	return engineCfg, err
}

func newCfgForManualLaunch(p ExternalPlugin, opts ...ManualLaunchOption) (*cfg, error) {
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
		socketPath := api.DaemonSocketPath()
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to default socket %q: %w", socketPath, err)
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

func restoreConfig(p ExternalPlugin) (*cfg, error) {
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
