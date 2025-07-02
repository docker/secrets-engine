package adaptation

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"connectrpc.com/connect"
	nri "github.com/containerd/nri/pkg/net"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/internal/ipc"
	"github.com/docker/secrets-engine/pkg/api"
	v1 "github.com/docker/secrets-engine/pkg/api/resolver/v1"
	"github.com/docker/secrets-engine/pkg/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/pkg/secrets"
)

var (
	pluginRegistrationTimeout = api.DefaultPluginRegistrationTimeout
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

var (
	_ secrets.Resolver = &plugin{}
)

type plugin struct {
	sync.Mutex
	base           string
	pattern        secrets.Pattern
	version        string
	cmd            *exec.Cmd
	pluginClient   resolverv1connect.PluginServiceClient
	resolverClient resolverv1connect.ResolverServiceClient
	close          func() error

	closed bool
}

// newLaunchedPlugin launches a pre-installed plugin with a pre-connected socket pair.
func newLaunchedPlugin(dir string, v setupValidator) (p *plugin, retErr error) {
	fullPath := filepath.Join(dir, v.name)
	if runtime.GOOS == "windows" {
		fullPath += ".exe"
	}

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

	cmd := exec.Command(fullPath)
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
	cmd.Env = []string{api.PluginLaunchedByEngineVar + "=" + envCfgStr}

	p = &plugin{
		cmd:  cmd,
		base: v.name,
	}

	if err = cmd.Start(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to launch plugin %q: %w", v.name, err)
	}
	cmdDone := make(chan struct{})
	go func() {
		// TODO: do something useful here and deal with the error
		_ = cmd.Wait()
		close(cmdDone)
	}()

	r, err := setup(conn, v)
	if err != nil {
		conn.Close()
		shutdownCMD(cmd, cmdDone)
		return nil, err
	}

	return &plugin{
		base:           v.name,
		pattern:        r.cfg.pattern,
		version:        r.cfg.version,
		cmd:            cmd,
		pluginClient:   resolverv1connect.NewPluginServiceClient(r.client, "http://unix"),
		resolverClient: resolverv1connect.NewResolverServiceClient(r.client, "http://unix"),
		close:          r.close,
	}, nil
}

// newExternalPlugin creates a plugin (stub) for an accepted external plugin connection.
func newExternalPlugin(conn net.Conn, v setupValidator) (*plugin, error) {
	r, err := setup(conn, v)
	if err != nil {
		return nil, err
	}
	return &plugin{
		base:           r.cfg.name,
		pattern:        r.cfg.pattern,
		version:        r.cfg.version,
		pluginClient:   resolverv1connect.NewPluginServiceClient(r.client, "http://unix"),
		resolverClient: resolverv1connect.NewResolverServiceClient(r.client, "http://unix"),
		close:          r.close,
	}, nil
}

func (p *plugin) GetSecret(ctx context.Context, request secrets.Request) (secrets.Envelope, error) {
	req := connect.NewRequest(v1.GetSecretRequest_builder{
		SecretId: proto.String(request.ID.String()),
	}.Build())
	resp, err := p.resolverClient.GetSecret(ctx, req)
	if err != nil {
		return envelopeErr(request, err), err
	}
	id, err := secrets.ParseID(resp.Msg.GetSecretId())
	if err != nil {
		return envelopeErr(request, err), err
	}
	if id != request.ID {
		return envelopeErr(request, secrets.ErrIDMismatch), secrets.ErrIDMismatch
	}
	return secrets.Envelope{
		ID:       id,
		Value:    []byte(resp.Msg.GetSecretValue()),
		Provider: p.base,
	}, nil
}

func envelopeErr(req secrets.Request, err error) secrets.Envelope {
	return secrets.Envelope{ID: req.ID, ResolvedAt: time.Now(), Error: err.Error()}
}
