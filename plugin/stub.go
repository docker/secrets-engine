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
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

// stub implements Stub.
type stub struct {
	name    string
	m       sync.Mutex
	factory func(ctx context.Context, onClose func(error)) (io.Closer, error)

	registrationTimeout time.Duration
	requestTimeout      time.Duration
}

var (
	ParseID          = secrets.ParseID
	MustParseID      = secrets.MustParseID
	ParsePattern     = secrets.ParsePattern
	MustParsePattern = secrets.MustParsePattern
	NewVersion       = api.NewVersion
	MustNewVersion   = api.MustNewVersion

	ErrSecretNotFound = secrets.ErrNotFound
)

func (c *Config) Valid() error {
	if c.Version == nil {
		return errors.New("version is required")
	}
	if c.Pattern == nil {
		return errors.New("pattern is required")
	}
	return nil
}

// New creates a stub with the given plugin and options.
// ManualLaunchOption only apply when the plugin is launched manually.
// If launched by the secrets runtime, they are ignored.
// If logger is nil, a default logger will be created and used.
func New(p ExternalPlugin, config Config, opts ...ManualLaunchOption) (Stub, error) {
	if err := config.Valid(); err != nil {
		return nil, err
	}
	if config.Logger == nil {
		config.Logger = logging.NewDefaultLogger("plugin")
	}
	cfg, err := newCfg(p, opts...)
	if err != nil {
		return nil, err
	}
	cfg.Config = config
	stub := &stub{
		name: cfg.name,
		factory: func(ctx context.Context, onClose func(error)) (io.Closer, error) {
			return setup(ctx, *cfg, onClose)
		},
	}
	config.Logger.Printf("Created plugin %s", cfg.name)

	return stub, nil
}

// Run the plugin. Start event processing then wait for an error or getting stopped.
func (stub *stub) Run(ctx context.Context) error {
	if !stub.m.TryLock() {
		return fmt.Errorf("already running")
	}
	defer stub.m.Unlock()
	errCh := make(chan error, 1)
	ipc, err := stub.factory(ctx, func(err error) {
		errCh <- err
	})
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case err = <-errCh:
	}
	return errors.Join(ipc.Close(), err)
}

func (stub *stub) RegistrationTimeout() time.Duration {
	return stub.registrationTimeout
}

func (stub *stub) RequestTimeout() time.Duration {
	return stub.requestTimeout
}
