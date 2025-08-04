package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/internal/api/resolver/v1"
	"github.com/docker/secrets-engine/internal/testhelper"
)

var (
	errMockValidator   = errors.New("mockValidatorErr")
	errMockRegistrator = errors.New("mockRegistratorErr")

	mockPluginCfgOut = pluginCfgOut{
		engineName:     "mockEngine",
		engineVersion:  "1.0.0",
		requestTimeout: 30 * time.Second,
	}
	mockPluginCfgInUnvalidated = pluginDataUnvalidated{
		Name:    "mockPlugin",
		Pattern: "*",
		Version: "1.0.0",
	}
	mockPluginCfgIn = mustNewValidatedConfig(mockPluginCfgInUnvalidated)
)

func mustNewValidatedConfig(in pluginDataUnvalidated) metadata {
	r, err := newValidatedConfig(in)
	if err != nil {
		panic(err)
	}
	return r
}

type mockValidator struct {
	t   *testing.T
	out *pluginCfgOut
	err error
}

func (m mockValidator) Validate(in pluginDataUnvalidated) (metadata, *pluginCfgOut, error) {
	assert.Equal(m.t, mockPluginCfgInUnvalidated, in)
	return mockPluginCfgIn, m.out, m.err
}

func mockValidatorOK(t *testing.T) pluginCfgInValidator {
	return mockValidator{
		t:   t,
		out: &mockPluginCfgOut,
	}
}

func mockValidatorErr(t *testing.T) pluginCfgInValidator {
	return mockValidator{
		t:   t,
		err: errMockValidator,
	}
}

func Test_registration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		v    pluginCfgInValidator
		test func(t *testing.T, r *registrationLogic, chResult chan registrationResult)
	}{
		{
			name: "can only register once",
			v:    mockValidatorOK(t),
			test: func(t *testing.T, r *registrationLogic, chResult chan registrationResult) {
				out, err := r.register(t.Context(), mockPluginCfgInUnvalidated)
				assert.Nil(t, err)
				assert.Equal(t, mockPluginCfgOut, *out)

				rr := <-chResult
				require.NoError(t, rr.err)
				assert.Equal(t, mockPluginCfgIn, rr.cfg)

				_, err = r.register(t.Context(), mockPluginCfgInUnvalidated)
				assert.ErrorContains(t, err, "cannot rerun registration")
			},
		},
		{
			name: "registration gets rejected if validation fails and can't be retried",
			v:    mockValidatorErr(t),
			test: func(t *testing.T, r *registrationLogic, chResult chan registrationResult) {
				_, err := r.register(t.Context(), mockPluginCfgInUnvalidated)
				assert.ErrorIs(t, err, errMockValidator)

				rr := <-chResult
				assert.ErrorIs(t, rr.err, errMockValidator)

				_, err = r.register(t.Context(), mockPluginCfgInUnvalidated)
				assert.ErrorContains(t, err, "cannot rerun registration")
			},
		},
		{
			name: "registration does not block but errors if channel is jammed",
			v:    mockValidatorOK(t),
			test: func(t *testing.T, r *registrationLogic, chResult chan registrationResult) {
				chResult <- registrationResult{}

				_, err := r.register(t.Context(), mockPluginCfgInUnvalidated)
				assert.ErrorContains(t, err, "registration rejected")

				_, err = r.register(t.Context(), mockPluginCfgInUnvalidated)
				assert.ErrorContains(t, err, "cannot rerun registration")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := make(chan registrationResult, 1)
			r := newRegistrationLogic(tt.v, c)
			tt.test(t, r, c)
		})
	}
}

type mockPluginRegistrator struct {
	t   *testing.T
	out *pluginCfgOut
	err error
}

func (m mockPluginRegistrator) register(_ context.Context, cfg pluginDataUnvalidated) (*pluginCfgOut, error) {
	assert.Equal(m.t, mockPluginCfgInUnvalidated, cfg)
	return m.out, m.err
}

func mockPluginRegistratorOK(t *testing.T) pluginRegistrator {
	return mockPluginRegistrator{
		t:   t,
		out: &mockPluginCfgOut,
	}
}

func mockPluginRegistratorErr(t *testing.T) pluginRegistrator {
	return mockPluginRegistrator{
		t:   t,
		err: errMockRegistrator,
	}
}

func Test_RegisterPlugin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    pluginRegistrator
		in   pluginDataUnvalidated
		test func(t *testing.T, resp *connect.Response[resolverv1.RegisterPluginResponse], err error)
	}{
		{
			name: "registration fails",
			r:    mockPluginRegistratorErr(t),
			in:   mockPluginCfgInUnvalidated,
			test: func(t *testing.T, _ *connect.Response[resolverv1.RegisterPluginResponse], err error) {
				assert.ErrorIs(t, err, errMockRegistrator)
			},
		},
		{
			name: "registration succeeds",
			r:    mockPluginRegistratorOK(t),
			in:   mockPluginCfgInUnvalidated,
			test: func(t *testing.T, resp *connect.Response[resolverv1.RegisterPluginResponse], err error) {
				assert.NoError(t, err)
				assert.Equal(t, mockPluginCfgOut.engineName, resp.Msg.GetEngineName())
				assert.Equal(t, mockPluginCfgOut.engineVersion, resp.Msg.GetEngineVersion())
				assert.Equal(t, mockPluginCfgOut.requestTimeout, resp.Msg.GetRequestTimeout().AsDuration())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &RegisterService{logger: testhelper.TestLogger(t), r: tt.r}
			req := resolverv1.RegisterPluginRequest_builder{
				Name:    proto.String(tt.in.Name),
				Version: proto.String(tt.in.Version),
				Pattern: proto.String(tt.in.Pattern),
			}.Build()
			resp, err := s.RegisterPlugin(t.Context(), connect.NewRequest(req))
			tt.test(t, resp, err)
		})
	}
}
