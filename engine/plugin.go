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

	"github.com/docker/secrets-engine/x/api"
	v1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/ipc"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
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

	metadata

	Closed() <-chan struct{}
}

type pluginType string

const (
	internalPlugin pluginType = "internal" // launched by the engine
	externalPlugin pluginType = "external" // launched externally
	builtinPlugin  pluginType = "builtin"  // no binary only Go interface
)

type runtimeImpl struct {
	metadata
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
	r, err := setup(logger, rwc, setIpcClosed, v, ipc.WithShutdownTimeout(getPluginShutdownTimeout()))
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
		metadata:       r.cfg,
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
	r, err := setup(logger, conn, once, v, ipc.WithShutdownTimeout(getPluginShutdownTimeout()))
	if err != nil {
		return nil, err
	}
	c := resolverv1connect.NewPluginServiceClient(r.client, "http://unix")
	return &runtimeImpl{
		metadata:       r.cfg,
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

func (r *runtimeImpl) GetSecrets(ctx context.Context, request secrets.Request) ([]secrets.Envelope, error) {
	req := connect.NewRequest(v1.GetSecretRequest_builder{
		Pattern:  proto.String(request.Pattern.String()),
		Provider: proto.String(request.Provider),
	}.Build())
	resp, err := r.resolverClient.GetSecrets(ctx, req)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			err = secrets.ErrNotFound
		}
		return secrets.EnvelopeErrs(err), err
	}
	var items []secrets.Envelope
	var errList []error

	for _, item := range resp.Msg.GetEnvelopes() {
		id, err := secrets.ParseID(item.GetId())
		if err != nil {
			errList = append(errList, err)
			items = append(items, secrets.EnvelopeErr(err))
			continue
		}
		items = append(items, secrets.Envelope{
			ID:         id,
			Value:      item.GetValue(),
			Provider:   r.Name().String(),
			Version:    item.GetVersion(),
			Error:      item.GetError(),
			CreatedAt:  item.GetCreatedAt().AsTime(),
			ResolvedAt: item.GetResolvedAt().AsTime(),
			ExpiresAt:  item.GetExpiresAt().AsTime(),
		})
	}
	return items, errors.Join(errList...)
}
