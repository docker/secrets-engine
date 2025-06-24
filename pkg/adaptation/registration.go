package adaptation

import (
	"context"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/pkg/api/resolver/v1"
	"github.com/docker/secrets-engine/pkg/api/resolver/v1/resolverv1connect"
)

var _ resolverv1connect.EngineServiceHandler = &RegisterService{}

// config to be sent to the plugin
type pluginCfgOut struct {
	config         string
	engineName     string
	engineVersion  string
	requestTimeout time.Duration
}

// config received from the plugin
type pluginCfgIn struct {
	name    string
	version string
	pattern string
}

type onRegisteredFunc func(ctx context.Context, cfg pluginCfgIn) error

type RegisterService struct {
	m            sync.Mutex
	onRegistered onRegisteredFunc
	sent         pluginCfgOut
}

func NewRegisterService(cfg pluginCfgOut, registeredFunc onRegisteredFunc) *RegisterService {
	return &RegisterService{
		sent:         cfg,
		onRegistered: registeredFunc,
	}
}

func (r *RegisterService) RegisterPlugin(ctx context.Context, c *connect.Request[resolverv1.RegisterPluginRequest]) (*connect.Response[resolverv1.RegisterPluginResponse], error) {
	r.m.Lock()
	defer r.m.Unlock()
	in := pluginCfgIn{
		name:    c.Msg.GetName(),
		version: c.Msg.GetVersion(),
		pattern: c.Msg.GetPattern(),
	}
	if err := r.onRegistered(ctx, in); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(resolverv1.RegisterPluginResponse_builder{
		EngineName:     proto.String(r.sent.engineName),
		EngineVersion:  proto.String(r.sent.engineVersion),
		Config:         proto.String(r.sent.config),
		RequestTimeout: proto.Int64(int64(r.sent.requestTimeout.Seconds())),
	}.Build()), nil
}
