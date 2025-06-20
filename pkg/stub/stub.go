package stub

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/docker/secrets-engine/pkg/secrets"
)

type Plugin interface {
	secrets.Resolver

	Config() Config

	Configure(context.Context, RuntimeConfig) error

	Shutdown(context.Context)
}

type RuntimeConfig struct {
	Config  string
	Engine  string
	Version string
}

type Config struct {
	Version string

	Pattern string
}

// Stub is the interface the stub provides for the plugin implementation.
type Stub interface {
	// RegistrationTimeout returns the registration timeout for the stub.
	// This is the default timeout if the plugin has not been started or
	// the timeout received in the Configure request otherwise.
	RegistrationTimeout() time.Duration
}

// stub implements Stub.
type stub struct {
	cfg
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
		cfg: *cfg,
	}
	logrus.Infof("Created plugin %s", stub.name)

	return stub, nil
}

func (stub *stub) RegistrationTimeout() time.Duration {
	return stub.registrationTimeout
}
