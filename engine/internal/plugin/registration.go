package plugin

import (
	"context"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

type Unvalidated struct {
	Name    string
	Version string
	Pattern string
}

// ConfigOut is sent to the plugin
type ConfigOut struct {
	EngineName     string
	EngineVersion  string
	RequestTimeout time.Duration
}

type ConfigValidator interface {
	Validate(Unvalidated) (Metadata, *ConfigOut, error)
}

type registrationLogic struct {
	m         sync.Mutex
	done      bool
	validator ConfigValidator
	result    chan RegistrationResult
}

func NewRegistrationLogic(validator ConfigValidator, result chan RegistrationResult) Registrator {
	return &registrationLogic{
		validator: validator,
		result:    result,
	}
}

func (l *registrationLogic) Register(_ context.Context, cfg Unvalidated) (*ConfigOut, error) {
	l.m.Lock()
	defer l.m.Unlock()
	if l.done {
		return nil, errors.New("cannot rerun registration")
	}
	l.done = true
	in, out, err := l.validator.Validate(cfg)
	select {
	case l.result <- RegistrationResult{Config: in, Err: err}:
	default:
		return nil, errors.New("registration rejected")
	}
	return out, err
}

var _ resolverv1connect.RegisterServiceHandler = &RegisterService{}

type Registrator interface {
	Register(ctx context.Context, cfg Unvalidated) (*ConfigOut, error)
}

type RegisterService struct {
	Logger            logging.Logger
	PluginRegistrator Registrator
}

func (r *RegisterService) RegisterPlugin(ctx context.Context, c *connect.Request[resolverv1.RegisterPluginRequest]) (*connect.Response[resolverv1.RegisterPluginResponse], error) {
	r.Logger.Printf("Received plugin registration request: %s@%s (pattern: %v)", c.Msg.GetName(), c.Msg.GetVersion(), c.Msg.GetPattern())
	in := Unvalidated{
		Name:    c.Msg.GetName(),
		Version: c.Msg.GetVersion(),
		Pattern: c.Msg.GetPattern(),
	}
	out, err := r.PluginRegistrator.Register(ctx, in)
	if errors.Is(err, secrets.ErrInvalidPattern) {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(resolverv1.RegisterPluginResponse_builder{
		EngineName:     proto.String(out.EngineName),
		EngineVersion:  proto.String(out.EngineVersion),
		RequestTimeout: durationpb.New(out.RequestTimeout),
	}.Build()), nil
}
