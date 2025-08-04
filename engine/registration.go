package engine

import (
	"context"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/docker/secrets-engine/internal/api"
	resolverv1 "github.com/docker/secrets-engine/internal/api/resolver/v1"
	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/logging"
	"github.com/docker/secrets-engine/internal/secrets"
)

var _ resolverv1connect.EngineServiceHandler = &RegisterService{}

// config to be sent to the plugin
type pluginCfgOut struct {
	engineName     string
	engineVersion  string
	requestTimeout time.Duration
}

type pluginRegistrator interface {
	register(ctx context.Context, cfg api.PluginDataUnvalidated) (*pluginCfgOut, error)
}

type RegisterService struct {
	logger logging.Logger
	r      pluginRegistrator
}

func (r *RegisterService) RegisterPlugin(ctx context.Context, c *connect.Request[resolverv1.RegisterPluginRequest]) (*connect.Response[resolverv1.RegisterPluginResponse], error) {
	r.logger.Printf("Reveived plugin registration request: %s@%s (pattern: %v)", c.Msg.GetName(), c.Msg.GetVersion(), c.Msg.GetPattern())
	in := api.PluginDataUnvalidated{
		Name:    c.Msg.GetName(),
		Version: c.Msg.GetVersion(),
		Pattern: c.Msg.GetPattern(),
	}
	out, err := r.r.register(ctx, in)
	if errors.Is(err, secrets.ErrInvalidPattern) {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(resolverv1.RegisterPluginResponse_builder{
		EngineName:     proto.String(out.engineName),
		EngineVersion:  proto.String(out.engineVersion),
		RequestTimeout: durationpb.New(out.requestTimeout),
	}.Build()), nil
}

type pluginCfgInValidator interface {
	Validate(api.PluginDataUnvalidated) (api.PluginData, *pluginCfgOut, error)
}

type registrationResult struct {
	cfg api.PluginData
	err error
}

type registrationLogic struct {
	m         sync.Mutex
	done      bool
	validator pluginCfgInValidator
	result    chan registrationResult
}

func newRegistrationLogic(validator pluginCfgInValidator, result chan registrationResult) *registrationLogic {
	return &registrationLogic{
		validator: validator,
		result:    result,
	}
}

func (l *registrationLogic) register(_ context.Context, cfg api.PluginDataUnvalidated) (*pluginCfgOut, error) {
	l.m.Lock()
	defer l.m.Unlock()
	if l.done {
		return nil, errors.New("cannot rerun registration")
	}
	l.done = true
	in, out, err := l.validator.Validate(cfg)
	select {
	case l.result <- registrationResult{cfg: in, err: err}:
	default:
		return nil, errors.New("registration rejected")
	}
	return out, err
}
