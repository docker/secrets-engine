package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"connectrpc.com/connect"
	nri "github.com/containerd/nri/pkg/net"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/internal/api"
	v1 "github.com/docker/secrets-engine/internal/api/resolver/v1"
	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/ipc"
	"github.com/docker/secrets-engine/pkg/secrets"
)

var (
	pluginRegistrationTimeout = api.DefaultPluginRegistrationTimeout
	pluginRequestTimeout      = api.DefaultPluginRequestTimeout
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

var _ secrets.Resolver = &runtimeImpl{}

type runtime interface {
	secrets.Resolver

	io.Closer

	Data() pluginData

	Closed() <-chan struct{}
}

type pluginType string

const (
	internalPlugin pluginType = "internal" // launched by the engine
	externalPlugin pluginType = "external" // launched externally
	builtinPlugin  pluginType = "builtin"  // no binary only Go interface
)

type pluginData struct {
	name    string
	pattern secrets.Pattern
	version string
	pluginType
}

func (d pluginData) qualifiedName() string {
	return fmt.Sprintf("%s:%s@%s (%s)", d.pluginType, d.name, d.version, d.pattern)
}

type runtimeImpl struct {
	pluginData
	pluginClient   resolverv1connect.PluginServiceClient
	resolverClient resolverv1connect.ResolverServiceClient
	close          func() error
	closed         <-chan struct{}
}

// newLaunchedPlugin launches a pre-installed plugin with a pre-connected socket pair.
func newLaunchedPlugin(cmd *exec.Cmd, v setupValidator) (runtime, error) {
	sockets, err := nri.NewSocketPair()
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin connection for plugin %q: %w", v.name, err)
	}
	defer sockets.Close()

	conn, err := sockets.LocalConn()
	if err != nil {
		return nil, fmt.Errorf("failed to set up local connection for plugin %q: %w", v.name, err)
	}

	peerFile := sockets.PeerFile()
	defer peerFile.Close()

	cmd.ExtraFiles = []*os.File{peerFile}
	envCfg := ipc.PluginConfigFromEngine{
		Name:                v.name,
		RegistrationTimeout: getPluginRegistrationTimeout(),
		Fd:                  3, // 0, 1, and 2 are reserved for stdin, stdout, and stderr -> we get the next
	}
	envCfgStr, err := envCfg.ToString()
	if err != nil {
		conn.Close()
		return nil, err
	}
	cmd.Env = append(cmd.Env, api.PluginLaunchedByEngineVar+"="+envCfgStr)

	if err = cmd.Start(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to launch plugin %q: %w", v.name, err)
	}
	w := newCmdWatchWrapper(v.name, cmd)

	closed := make(chan struct{})
	once := sync.OnceFunc(func() { close(closed) })
	r, err := setup(conn, once, v)
	if err != nil {
		conn.Close()
		w.close()
		return nil, err
	}

	return &runtimeImpl{
		pluginData: pluginData{
			name:       v.name,
			pattern:    r.cfg.pattern,
			version:    r.cfg.version,
			pluginType: internalPlugin,
		},
		pluginClient:   resolverv1connect.NewPluginServiceClient(r.client, "http://unix"),
		resolverClient: resolverv1connect.NewResolverServiceClient(r.client, "http://unix"),
		close: sync.OnceValue(func() error {
			return errors.Join(r.close(), w.close())
		}),
		closed: closed,
	}, nil
}

// newExternalPlugin creates a plugin (stub) for an accepted external plugin connection.
func newExternalPlugin(conn net.Conn, v setupValidator) (runtime, error) {
	closed := make(chan struct{})
	once := sync.OnceFunc(func() { close(closed) })
	r, err := setup(conn, once, v)
	if err != nil {
		return nil, err
	}
	return &runtimeImpl{
		pluginData: pluginData{
			name:       r.cfg.name,
			pattern:    r.cfg.pattern,
			version:    r.cfg.version,
			pluginType: externalPlugin,
		},
		pluginClient:   resolverv1connect.NewPluginServiceClient(r.client, "http://unix"),
		resolverClient: resolverv1connect.NewResolverServiceClient(r.client, "http://unix"),
		close:          r.close,
		closed:         closed,
	}, nil
}

func (r *runtimeImpl) Close() error {
	return r.close()
}

func (r *runtimeImpl) Closed() <-chan struct{} {
	return r.closed
}

func (r *runtimeImpl) Data() pluginData {
	return r.pluginData
}

func (r *runtimeImpl) GetSecret(ctx context.Context, request secrets.Request) (secrets.Envelope, error) {
	req := connect.NewRequest(v1.GetSecretRequest_builder{
		Id:       proto.String(request.ID.String()),
		Provider: proto.String(request.Provider),
	}.Build())
	resp, err := r.resolverClient.GetSecret(ctx, req)
	if err != nil {
		return api.EnvelopeErr(request, err), err
	}
	id, err := secrets.ParseID(resp.Msg.GetId())
	if err != nil {
		return api.EnvelopeErr(request, err), err
	}
	if id != request.ID {
		return api.EnvelopeErr(request, secrets.ErrIDMismatch), secrets.ErrIDMismatch
	}
	return secrets.Envelope{
		ID:         id,
		Value:      resp.Msg.GetValue(),
		Provider:   r.name,
		Version:    resp.Msg.GetVersion(),
		Error:      resp.Msg.GetError(),
		CreatedAt:  resp.Msg.GetCreatedAt().AsTime(),
		ResolvedAt: resp.Msg.GetResolvedAt().AsTime(),
		ExpiresAt:  resp.Msg.GetExpiresAt().AsTime(),
	}, nil
}
