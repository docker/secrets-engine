package stub

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"

	resolverv1 "github.com/docker/secrets-engine/pkg/api/resolver/v1"
)

// MockConfigure implements the ConfigureInterface for testing.
type MockConfigure struct {
	t      *testing.T
	called atomic.Int32
	expectedConfigure
	cfg *Config
	err error
}

type expectedConfigure struct {
	config  string
	engine  string
	version string
}

func (m *MockConfigure) Configure(_ context.Context, config, engine, version string) (*Config, error) {
	m.called.Add(1)
	assert.Equal(m.t, m.expectedConfigure.config, config)
	assert.Equal(m.t, m.expectedConfigure.engine, engine)
	assert.Equal(m.t, m.expectedConfigure.version, version)
	return m.cfg, m.err
}

func newMockConfigure(t *testing.T, cfg *Config, err error, expected expectedConfigure) *MockConfigure {
	return &MockConfigure{
		t:                 t,
		cfg:               cfg,
		err:               err,
		expectedConfigure: expected,
	}
}

func TestConfigure_AllSuccess(t *testing.T) {
	expCfg := expectedConfigure{
		config:  "myconfig",
		engine:  "engineA",
		version: "1.0",
	}
	dynamicCfg := cfgFromEngine{
		engineName:     expCfg.engine,
		engineVersion:  expCfg.version,
		requestTimeout: 500 * time.Millisecond,
	}
	mockCfg := &Config{Version: "v1.2.3", Pattern: "test-*"}
	mock := newMockConfigure(t, mockCfg, nil, expCfg)
	service := newConfigureService("pluginX", mock, nil)
	cfg, err := service.GetConfig()
	assert.NoError(t, err)
	assert.Nil(t, cfg)

	chErrWaitUntilConfigured := make(chan error)
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		chErrWaitUntilConfigured <- service.WaitUntilConfigured(ctx)
	}()
	cancel()
	errWaitUntilConfigured := <-chErrWaitUntilConfigured
	assert.NoError(t, errWaitUntilConfigured)

	req := connect.NewRequest(resolverv1.ConfigureRequest_builder{
		Config:         proto.String(expCfg.config),
		EngineName:     proto.String(expCfg.engine),
		EngineVersion:  proto.String(expCfg.version),
		RequestTimeout: proto.Int64(int64(dynamicCfg.requestTimeout / time.Millisecond)),
	}.Build())

	go func() {
		retErr := service.WaitUntilConfigured(t.Context())
		cfg, err := service.GetConfig()
		assert.NoError(t, err)
		assert.Equal(t, dynamicCfg, *cfg)
		chErrWaitUntilConfigured <- retErr
	}()

	resp, err := service.Configure(context.Background(), req)

	assert.NoError(t, err)
	assert.Equal(t, int32(1), mock.called.Load())
	assert.Equal(t, mockCfg.Version, resp.Msg.GetVersion())
	assert.Equal(t, mockCfg.Pattern, resp.Msg.GetPattern())
	errWaitUntilConfigured = <-chErrWaitUntilConfigured
	assert.NoError(t, errWaitUntilConfigured)

	_, err = service.Configure(context.Background(), connect.NewRequest(&resolverv1.ConfigureRequest{}))
	assert.Error(t, err)
	assert.Equal(t, int32(1), mock.called.Load())
}

func TestConfigure_PluginConfigureFailed(t *testing.T) {
	expCfg := expectedConfigure{
		config:  "myconfig",
		engine:  "engineA",
		version: "1.0",
	}
	dynamicCfg := cfgFromEngine{
		engineName:     expCfg.engine,
		engineVersion:  expCfg.version,
		requestTimeout: 500 * time.Millisecond,
	}
	errPluginConfigure := errors.New("plugin configure failed")
	mock := newMockConfigure(t, nil, errPluginConfigure, expCfg)
	service := newConfigureService("pluginX", mock, nil)
	req := connect.NewRequest(resolverv1.ConfigureRequest_builder{
		Config:         proto.String(expCfg.config),
		EngineName:     proto.String(expCfg.engine),
		EngineVersion:  proto.String(expCfg.version),
		RequestTimeout: proto.Int64(int64(dynamicCfg.requestTimeout / time.Millisecond)),
	}.Build())

	chErrWaitUntilConfigured := make(chan error)
	go func() {
		retErr := service.WaitUntilConfigured(t.Context())
		chErrWaitUntilConfigured <- retErr
	}()

	_, err := service.Configure(context.Background(), req)
	assert.Error(t, err)
	errWaitUntilConfigured := <-chErrWaitUntilConfigured
	assert.Equal(t, errPluginConfigure, errWaitUntilConfigured)

	_, err = service.GetConfig()
	assert.Equal(t, errPluginConfigure, err)

	_, err = service.Configure(context.Background(), connect.NewRequest(&resolverv1.ConfigureRequest{}))
	assert.Error(t, err)
	assert.Equal(t, int32(1), mock.called.Load())
}
