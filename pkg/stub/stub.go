package stub

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/docker/secrets-engine/pkg/secrets"
)

type Plugin interface {
	secrets.Resolver

	Shutdown(context.Context)
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
func New(p Plugin, opts ...Option) (Stub, error) {
	cfg, err := newCfg(p, opts...)
	if err != nil {
		return nil, err
	}
	stub := &stub{
		cfg: *cfg,
	}
	logrus.Infof("Created plugin %s", stub.FullName())

	return stub, nil
}

func (stub *stub) RegistrationTimeout() time.Duration {
	return stub.registrationTimeout
}
