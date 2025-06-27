package adaptation

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/pkg/api"
	v1 "github.com/docker/secrets-engine/pkg/api/resolver/v1"
	"github.com/docker/secrets-engine/pkg/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/pkg/secrets"
)

var (
	pluginRegistrationTimeout = api.DefaultPluginRegistrationTimeout
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
	_ = (secrets.Resolver)((*plugin)(nil))
)

type plugin struct {
	sync.Mutex
	base           string
	pattern        secrets.Pattern
	version        string
	pluginClient   resolverv1connect.PluginServiceClient
	resolverClient resolverv1connect.ResolverServiceClient
	close          func() error
}

// newExternalPlugin Create a plugin (stub) for an accepted external plugin connection.
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

var (
	errIDMismatch = errors.New("id mismatch")
)

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
		return envelopeErr(request, errIDMismatch), errIDMismatch
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
