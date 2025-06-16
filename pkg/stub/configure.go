package stub

import (
	"context"
	"errors"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/pkg/api/resolver/v1"
	"github.com/docker/secrets-engine/pkg/api/resolver/v1/resolverv1connect"
)

var _ = (resolverv1connect.PluginServiceHandler)((*cfgService)(nil))

// ConfigureInterface handles Configure API request.
type ConfigureInterface interface {
	// Configure the plugin with the given NRI-supplied configuration.
	Configure(ctx context.Context, config, engine, version string) (*Config, error)
}

type Config struct {
	Version string
	Pattern string
}

// The config returned from the secrets engine.
type cfgFromEngine struct {
	engineName     string
	engineVersion  string
	requestTimeout time.Duration
}

type cfgService struct {
	m                    sync.Mutex
	pluginName           string
	configure            ConfigureInterface
	shutdown             func(context.Context)
	done                 chan struct{}
	config               cfgFromEngine
	pluginCfgCallbackErr error
}

func newConfigureService(pluginName string, configure ConfigureInterface, shutdown func(context.Context)) *cfgService {
	return &cfgService{
		pluginName: pluginName,
		configure:  configure,
		shutdown:   shutdown,
		done:       make(chan struct{}),
	}
}

func (s *cfgService) Configure(ctx context.Context, c *connect.Request[resolverv1.ConfigureRequest]) (*connect.Response[resolverv1.ConfigureResponse], error) {
	s.m.Lock()
	defer s.m.Unlock()
	select {
	case <-s.done:
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("plugin already configured"))
	default:
	}
	defer func() {
		close(s.done)
	}()
	engineName := c.Msg.GetEngineName()
	engineVersion := c.Msg.GetEngineVersion()
	logrus.Infof("Configuring plugin %s for engine %s/%s...", s.pluginName, engineName, engineVersion)

	s.config = cfgFromEngine{
		engineName:     engineName,
		engineVersion:  engineVersion,
		requestTimeout: time.Duration(c.Msg.GetRequestTimeout() * int64(time.Millisecond)),
	}

	cfg, err := s.configure.Configure(ctx, c.Msg.GetConfig(), engineName, engineVersion)
	if err != nil {
		logrus.Errorf("Plugin configuration failed: %v", err)
		s.pluginCfgCallbackErr = err
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(resolverv1.ConfigureResponse_builder{
		Version: proto.String(cfg.Version),
		Pattern: proto.String(cfg.Pattern),
	}.Build()), nil
}

func (s *cfgService) Shutdown(ctx context.Context, _ *connect.Request[resolverv1.ShutdownRequest]) (*connect.Response[resolverv1.ShutdownResponse], error) {
	if s.shutdown != nil {
		s.shutdown(ctx)
	}
	return connect.NewResponse(&resolverv1.ShutdownResponse{}), nil
}

func (s *cfgService) WaitUntilConfigured(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
	}
	return s.pluginCfgCallbackErr
}

func (s *cfgService) GetConfig() (*cfgFromEngine, error) {
	s.m.Lock()
	defer s.m.Unlock()
	return &s.config, s.pluginCfgCallbackErr
}
