package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/runtime/internal/config"
	"github.com/docker/secrets-engine/runtime/internal/plugin"
	"github.com/docker/secrets-engine/x/api"
	v1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/ipc"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"

	// register the plugin routes
	// this will most likely move or get cleaned up once this file and its
	// associated dependencies get moved to the internal package.
	_ "github.com/docker/secrets-engine/runtime/internal/routes/plugin"
)

var (
	pluginRegistrationTimeout = api.DefaultPluginRegistrationTimeout
	pluginRequestTimeout      = api.DefaultClientRequestTimeout
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

func GetPluginRequestTimeout() time.Duration {
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

func GetPluginShutdownTimeout() time.Duration {
	timeoutCfgLock.RLock()
	defer timeoutCfgLock.RUnlock()
	return pluginShutdownTimeout
}

var _ secrets.Resolver = &runtimeImpl{}

type runtimeImpl struct {
	plugin.Metadata
	pluginClient   resolverv1connect.PluginServiceClient
	resolverClient resolverv1connect.ResolverServiceClient
	close          func() error
	closed         <-chan struct{}
	logger         logging.Logger
	// TODO: actually store the PID here (we'll need this for security reasons later anyway)
	cmd plugin.Watcher
}

// newLaunchedPlugin launches a pre-installed plugin with a pre-connected socket pair.
func newLaunchedPlugin(cfg Config, cmd *exec.Cmd) (plugin.ExternalRuntime, error) {
	rwc, fd, err := ipc.NewConnectionPair(cmd)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	envCfg := &ipc.PluginConfigFromEngine{
		Name:                cfg.Name(),
		RegistrationTimeout: getPluginRegistrationTimeout(),
		Custom:              fd.ToCustomCfg(),
	}
	envCfgStr, err := envCfg.ToString()
	if err != nil {
		rwc.Close()
		return nil, err
	}
	cmd.Env = append(cmd.Env, api.PluginLaunchedByEngineVar+"="+envCfgStr)

	process := plugin.NewProcess(cmd)
	watcher := plugin.WatchProcess(cfg.Logger(), cfg.Name(), process, GetPluginShutdownTimeout())

	ipcClosed, setIpcClosed := closeOnce()
	r, err := setup(cfg, rwc, setIpcClosed, ipc.WithShutdownTimeout(GetPluginShutdownTimeout()))
	if err != nil {
		rwc.Close()
		watcher.Close()
		return nil, err
	}

	c := resolverv1connect.NewPluginServiceClient(r.client, "http://unix")
	helper := plugin.NewShutdownHelper(func() error {
		return errors.Join(callPluginShutdown(c, ipcClosed), filterClientAlreadyClosed(r.close()), watcher.Close())
	})

	go func() {
		<-watcher.Closed()
		_ = helper.Shutdown(fmt.Errorf("plugin '%s' stopped unexpectedly", cfg.Name()))
	}()

	return &runtimeImpl{
		Metadata:       r.cfg,
		pluginClient:   c,
		resolverClient: resolverv1connect.NewResolverServiceClient(r.client, "http://unix"),
		close: func() error {
			return helper.Shutdown(nil)
		},
		closed: helper.Closed(),
		logger: cfg.Logger(),
		cmd:    watcher,
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
	ctx, cancel := context.WithTimeout(context.Background(), GetPluginShutdownTimeout())
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

// NewExternalPlugin creates a plugin (stub) for an accepted external plugin connection.
func NewExternalPlugin(cfg Config, conn io.ReadWriteCloser) (plugin.Runtime, error) {
	closed := make(chan struct{})
	once := sync.OnceFunc(func() { close(closed) })
	r, err := setup(cfg, conn, once, ipc.WithShutdownTimeout(GetPluginShutdownTimeout()))
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
		logger: cfg.Logger(),
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
			Metadata:   item.GetMetadata(),
			Provider:   r.Name().String(),
			Version:    item.GetVersion(),
			CreatedAt:  item.GetCreatedAt().AsTime(),
			ResolvedAt: item.GetResolvedAt().AsTime(),
			ExpiresAt:  item.GetExpiresAt().AsTime(),
		})
	}
	return items, nil
}

func (r *runtimeImpl) Watcher() plugin.Watcher {
	return r.cmd
}

func NewLauncher(cfg config.Engine, pluginFile string) (string, func() (plugin.Runtime, error)) {
	name := toDisplayName(pluginFile)
	return name, func() (plugin.Runtime, error) {
		runtimeConfig := NewRuntimeConfig(
			name,
			plugin.ConfigOut{
				EngineName:     cfg.Name(),
				EngineVersion:  cfg.Version(),
				RequestTimeout: GetPluginRequestTimeout(),
			},
			cfg,
		)
		return newLaunchedPlugin(runtimeConfig, exec.Command(filepath.Join(cfg.PluginPath(), pluginFile)))
	}
}

func toDisplayName(filename string) string {
	return strings.TrimSuffix(filename, ".exe")
}
