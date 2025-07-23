package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/docker/secrets-engine/internal/secrets"
)

type Plugin interface {
	secrets.Resolver

	Config() Config
}

type Config struct {
	Version string

	Pattern secrets.Pattern
}

// Stub is the interface the stub provides for the plugin implementation.
type Stub interface {
	// Run starts the plugin then waits for the plugin service to exit, either due to a
	// critical error or by cancelling the context. Calling Run() while the plugin is running,
	// will result in an error. After the plugin service exits, Run() can safely be called again.
	Run(context.Context) error

	// RegistrationTimeout returns the registration timeout for the stub.
	// This is the default timeout if the plugin has not been started or
	// the timeout received in the Configure request otherwise.
	RegistrationTimeout() time.Duration

	// RequestTimeout returns the request timeout for the stub.
	// This is the default timeout if the plugin has not been started or
	// the timeout received in the Configure request otherwise.
	RequestTimeout() time.Duration
}

// stub implements Stub.
type stub struct {
	name    string
	m       sync.Mutex
	factory func(ctx context.Context, onClose func(error)) (io.Closer, error)

	registrationTimeout time.Duration
	requestTimeout      time.Duration
}

// New creates a stub with the given plugin and options.
// ManualLaunchOption only apply when the plugin is launched manually.
// If launched by the secrets engine, they are ignored.
func New(p Plugin, opts ...ManualLaunchOption) (Stub, error) {
	cfg, err := newCfg(p, opts...)
	if err != nil {
		return nil, err
	}
	stub := &stub{
		name: cfg.name,
		factory: func(ctx context.Context, onClose func(error)) (io.Closer, error) {
			return setup(ctx, *cfg, onClose)
		},
	}
	logrus.Infof("Created plugin %s", cfg.name)

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
