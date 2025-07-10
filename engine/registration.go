package engine

import (
	"context"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/internal/api/resolver/v1"
	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/pkg/secrets"
)

var _ resolverv1connect.EngineServiceHandler = &RegisterService{}

// config to be sent to the plugin
type pluginCfgOut struct {
	engineName     string
	engineVersion  string
	requestTimeout time.Duration
}

// config received from the plugin
type pluginCfgIn struct {
	name    string
	version string
	pattern secrets.Pattern
}

type pluginRegistrator interface {
	register(ctx context.Context, cfg pluginCfgIn) (*pluginCfgOut, error)
}

type RegisterService struct {
	r pluginRegistrator
}

func (r *RegisterService) RegisterPlugin(ctx context.Context, c *connect.Request[resolverv1.RegisterPluginRequest]) (*connect.Response[resolverv1.RegisterPluginResponse], error) {
	logrus.Infof("Reveived plugin registration request: %s@%s (pattern: %v)", c.Msg.GetName(), c.Msg.GetVersion(), c.Msg.GetPattern())
	in := pluginCfgIn{
		name:    c.Msg.GetName(),
		version: c.Msg.GetVersion(),
		pattern: secrets.Pattern(c.Msg.GetPattern()),
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
		RequestTimeout: proto.Int64(int64(out.requestTimeout.Seconds())),
	}.Build()), nil
}

type pluginCfgInValidator interface {
	Validate(pluginCfgIn) (*pluginCfgOut, error)
}

type registrationResult struct {
	cfg pluginCfgIn
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

func (l *registrationLogic) register(_ context.Context, cfg pluginCfgIn) (*pluginCfgOut, error) {
	l.m.Lock()
	defer l.m.Unlock()
	if l.done {
		return nil, errors.New("cannot rerun registration")
	}
	l.done = true
	out, err := l.validator.Validate(cfg)
	select {
	case l.result <- registrationResult{cfg: cfg, err: err}:
	default:
		return nil, errors.New("registration rejected")
	}
	return out, err
}
