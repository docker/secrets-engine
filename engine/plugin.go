package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/internal/api"
	v1 "github.com/docker/secrets-engine/internal/api/resolver/v1"
	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/ipc"
	"github.com/docker/secrets-engine/internal/logging"
	"github.com/docker/secrets-engine/internal/secrets"
)

var (
	pluginRegistrationTimeout = api.DefaultPluginRegistrationTimeout
	pluginRequestTimeout      = api.DefaultPluginRequestTimeout
	pluginShutdownTimeout     = 2 * time.Second
	timeoutCfgLock            sync.RWMutex
)

// SetPluginRegistrationTimeout sets the timeout for plugin registration.
func SetPluginRegistrationTimeout(t time.Duration) {
	timeoutCfgLock.Lock()
	defer timeoutCfgLock.Unlock()
	pluginRegistrationTimeout = t
}

func getPluginRegistrationTimeout() time.Duration {
	timeoutCfgLock.RLock()
	defer timeoutCfgLock.RUnlock()
	return pluginRegistrationTimeout
}

// SetPluginRequestTimeout sets the timeout for plugins to handle a request.
func SetPluginRequestTimeout(t time.Duration) {
	timeoutCfgLock.Lock()
	defer timeoutCfgLock.Unlock()
	pluginRequestTimeout = t
}

func getPluginRequestTimeout() time.Duration {
	timeoutCfgLock.RLock()
	defer timeoutCfgLock.RUnlock()
	return pluginRequestTimeout
}

// SetPluginShutdownTimeout sets the timeout for plugins to handle a request.
func SetPluginShutdownTimeout(t time.Duration) {
	timeoutCfgLock.Lock()
	defer timeoutCfgLock.Unlock()
	pluginShutdownTimeout = t
}

func getPluginShutdownTimeout() time.Duration {
	timeoutCfgLock.RLock()
	defer timeoutCfgLock.RUnlock()
	return pluginShutdownTimeout
}

var _ secrets.Resolver = &runtimeImpl{}

type runtime interface {
	secrets.Resolver

	io.Closer

	Data() api.PluginData

	Closed() <-chan struct{}
}

type pluginType string

const (
	internalPlugin pluginType = "internal" // launched by the engine
	externalPlugin pluginType = "external" // launched externally
	builtinPlugin  pluginType = "builtin"  // no binary only Go interface
)

type runtimeImpl struct {
	api.PluginData
	pluginClient   resolverv1connect.PluginServiceClient
	resolverClient resolverv1connect.ResolverServiceClient
	close          func() error
	closed         <-chan struct{}
}

// newLaunchedPlugin launches a pre-installed plugin with a pre-connected socket pair.
func newLaunchedPlugin(logger logging.Logger, cmd *exec.Cmd, v runtimeCfg) (runtime, error) {
	rwc, fd, err := ipc.NewConnectionPair(cmd)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	envCfg := &ipc.PluginConfigFromEngine{
		Name:                v.name,
		RegistrationTimeout: getPluginRegistrationTimeout(),
		Custom:              fd.ToCustomCfg(),
	}
	envCfgStr, err := envCfg.ToString()
	if err != nil {
		rwc.Close()
		return nil, err
	}
	cmd.Env = append(cmd.Env, api.PluginLaunchedByEngineVar+"="+envCfgStr)

	cmdWrapper := launchCmdWatched(logger, v.name, fromCmd(cmd), getPluginShutdownTimeout())

	ipcClosed, setIpcClosed := closeOnce()
	r, err := setup(logger, rwc, ipc.NewServerIPC, setIpcClosed, v, ipc.WithShutdownTimeout(getPluginShutdownTimeout()))
	if err != nil {
		rwc.Close()
		cmdWrapper.Close()
		return nil, err
	}

	c := resolverv1connect.NewPluginServiceClient(r.client, "http://unix")
	helper := newShutdownHelper(func() error {
		return errors.Join(callPluginShutdown(c, ipcClosed), r.close(), cmdWrapper.Close())
	})

	go func() {
		<-cmdWrapper.Closed()
		_ = helper.shutdown(fmt.Errorf("plugin '%s' stopped unexpectedly", v.name))
	}()

	return &runtimeImpl{
		PluginData:     r.cfg,
		pluginClient:   c,
		resolverClient: resolverv1connect.NewResolverServiceClient(r.client, "http://unix"),
		close: func() error {
			return helper.shutdown(nil)
		},
		closed: helper.closed(),
	}, nil
}

func closeOnce() (<-chan struct{}, func()) {
	ch := make(chan struct{})
	return ch, sync.OnceFunc(func() { close(ch) })
}

func callPluginShutdown(c resolverv1connect.PluginServiceClient, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), getPluginShutdownTimeout())
	defer cancel()
	_, err := c.Shutdown(ctx, connect.NewRequest(v1.ShutdownRequest_builder{}.Build()))
	return err
}

// newExternalPlugin creates a plugin (stub) for an accepted external plugin connection.
func newExternalPlugin(logger logging.Logger, conn io.ReadWriteCloser, v runtimeCfg) (runtime, error) {
	closed := make(chan struct{})
	once := sync.OnceFunc(func() { close(closed) })
	r, err := setup(logger, conn, ipc.NewClientIPC, once, v, ipc.WithShutdownTimeout(getPluginShutdownTimeout()))
	if err != nil {
		return nil, err
	}
	c := resolverv1connect.NewPluginServiceClient(r.client, "http://unix")
	return &runtimeImpl{
		PluginData:     r.cfg,
		pluginClient:   c,
		resolverClient: resolverv1connect.NewResolverServiceClient(r.client, "http://unix"),
		close: sync.OnceValue(func() error {
			return errors.Join(callPluginShutdown(c, closed), r.close())
		}),
		closed: closed,
	}, nil
}

func (r *runtimeImpl) Close() error {
	return r.close()
}

func (r *runtimeImpl) Closed() <-chan struct{} {
	return r.closed
}

func (r *runtimeImpl) Data() api.PluginData {
	return r.PluginData
}

func (r *runtimeImpl) GetSecret(ctx context.Context, request secrets.Request) (secrets.Envelope, error) {
	req := connect.NewRequest(v1.GetSecretRequest_builder{
		Id:       proto.String(request.ID.String()),
		Provider: proto.String(request.Provider),
	}.Build())
	resp, err := r.resolverClient.GetSecret(ctx, req)
	if err != nil {
		return secrets.EnvelopeErr(request, err), err
	}
	id, err := secrets.ParseID(resp.Msg.GetId())
	if err != nil {
		return secrets.EnvelopeErr(request, err), err
	}
	if id != request.ID {
		return secrets.EnvelopeErr(request, secrets.ErrIDMismatch), secrets.ErrIDMismatch
	}
	return secrets.Envelope{
		ID:         id,
		Value:      resp.Msg.GetValue(),
		Provider:   r.Name(),
		Version:    resp.Msg.GetVersion(),
		Error:      resp.Msg.GetError(),
		CreatedAt:  resp.Msg.GetCreatedAt().AsTime(),
		ResolvedAt: resp.Msg.GetResolvedAt().AsTime(),
		ExpiresAt:  resp.Msg.GetExpiresAt().AsTime(),
	}, nil
}
