package stub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/docker/secrets-engine/internal/ipc"
	"github.com/docker/secrets-engine/pkg/api/resolver/v1/resolverv1connect"
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
	factory func(context.Context) (ipc.PluginIPC, error)

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
		factory: func(ctx context.Context) (ipc.PluginIPC, error) {
			return setup(ctx, cfg.conn, cfg.name, p, cfg.registrationTimeout)
		},
	}
	logrus.Infof("Created plugin %s", cfg.name)

	return stub, nil
}

func setup(ctx context.Context, conn net.Conn, name string, p Plugin, timeout time.Duration) (ipc.PluginIPC, error) {
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	httpMux.Handle(resolverv1connect.NewPluginServiceHandler(&pluginService{p.Shutdown}))
	httpMux.Handle(resolverv1connect.NewResolverServiceHandler(&resolverService{p}))
	ipc, err := ipc.NewPluginIPC(conn, httpMux)
	if err != nil {
		return nil, err
	}
	runtimeCfg, err := doRegister(ctx, ipc.Conn(), name, p, timeout)
	if err != nil {
		ipc.Close()
		return nil, err
	}
	if err := p.Configure(ctx, *runtimeCfg); err != nil {
		ipc.Close()
		return nil, fmt.Errorf("failed to configure plugin %q: %w", name, err)
	}
	logrus.Infof("Started plugin %s...", name)
	return ipc, nil
}

// Run the plugin. Start event processing then wait for an error or getting stopped.
func (stub *stub) Run(ctx context.Context) error {
	if !stub.m.TryLock() {
		return fmt.Errorf("already running")
	}
	defer stub.m.Unlock()
	ipc, err := stub.factory(ctx)
	if err != nil {
		return err
	}
	err = ipc.Wait(ctx)
	select {
	case <-ctx.Done():
	default:
	}
	return errors.Join(ipc.Close(), err)
}

func (stub *stub) RegistrationTimeout() time.Duration {
	return stub.registrationTimeout
}

func (stub *stub) RequestTimeout() time.Duration {
	return stub.requestTimeout
}
