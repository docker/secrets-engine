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
	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/engine/internal/plugin"
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

type pluginType string

const (
	internalPlugin pluginType = "internal" // launched by the engine
	externalPlugin pluginType = "external" // launched externally
	builtinPlugin  pluginType = "builtin"  // no binary only Go interface
)

type runtimeImpl struct {
	plugin.Metadata
	pluginClient   resolverv1connect.PluginServiceClient
	resolverClient resolverv1connect.ResolverServiceClient
	close          func() error
	closed         <-chan struct{}
	logger         logging.Logger
	// TODO: actually store the PID here (we'll need this for security reasons later anyway)
	cmd procWrapper
}

// newLaunchedPlugin launches a pre-installed plugin with a pre-connected socket pair.
func newLaunchedPlugin(logger logging.Logger, cmd *exec.Cmd, v runtimeCfg) (plugin.Runtime, error) {
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
		return errors.Join(callPluginShutdown(c, ipcClosed), filterClientAlreadyClosed(r.close()), cmdWrapper.Close())
	})

	go func() {
		<-cmdWrapper.Closed()
		_ = helper.shutdown(fmt.Errorf("plugin '%s' stopped unexpectedly", v.name))
	}()

	return &runtimeImpl{
		Metadata:       r.cfg,
		pluginClient:   c,
		resolverClient: resolverv1connect.NewResolverServiceClient(r.client, "http://unix"),
		close: func() error {
			return helper.shutdown(nil)
		},
		closed: helper.closed(),
		logger: logger,
		cmd:    cmdWrapper,
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

func filterClientAlreadyClosed(err error) error {
	if errors.Is(err, yamux.ErrRemoteGoAway) {
		return nil
	}
	return err
}

// newExternalPlugin creates a plugin (stub) for an accepted external plugin connection.
func newExternalPlugin(logger logging.Logger, conn io.ReadWriteCloser, v runtimeCfg) (plugin.Runtime, error) {
	closed := make(chan struct{})
	once := sync.OnceFunc(func() { close(closed) })
	r, err := setup(logger, conn, once, v, ipc.WithShutdownTimeout(getPluginShutdownTimeout()))
	if err != nil {
		return nil, err
	}
	c := resolverv1connect.NewPluginServiceClient(r.client, "http://unix")
	return &runtimeImpl{
		Metadata:       r.cfg,
		pluginClient:   c,
		resolverClient: resolverv1connect.NewResolverServiceClient(r.client, "http://unix"),
		close: sync.OnceValue(func() error {
			return errors.Join(callPluginShutdown(c, closed), filterClientAlreadyClosed(r.close()))
		}),
		closed: closed,
		logger: logger,
	}, nil
}

func (r *runtimeImpl) Close() error {
	return r.close()
}

func (r *runtimeImpl) Closed() <-chan struct{} {
	return r.closed
}

func (r *runtimeImpl) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	req := connect.NewRequest(v1.GetSecretsRequest_builder{
		Pattern: proto.String(pattern.String()),
	}.Build())
	resp, err := r.resolverClient.GetSecrets(ctx, req)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			err = secrets.ErrNotFound
		}
		return nil, err
	}

	var items []secrets.Envelope
	for _, item := range resp.Msg.GetEnvelopes() {
		id, err := secrets.ParseID(item.GetId())
		if err != nil {
			r.logger.Errorf("parsing ID: %s", err)
			continue
		}
		items = append(items, secrets.Envelope{
			ID:         id,
			Value:      item.GetValue(),
			Provider:   r.Name().String(),
			Version:    item.GetVersion(),
			CreatedAt:  item.GetCreatedAt().AsTime(),
			ResolvedAt: item.GetResolvedAt().AsTime(),
			ExpiresAt:  item.GetExpiresAt().AsTime(),
		})
	}
	return items, nil
}
