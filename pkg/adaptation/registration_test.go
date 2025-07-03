package adaptation

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/pkg/api/resolver/v1"
)

var (
	errMockValidator   = errors.New("mockValidatorErr")
	errMockRegistrator = errors.New("mockRegistratorErr")

	mockPluginCfgOut = pluginCfgOut{
		engineName:     "mockEngine",
		engineVersion:  "1.0.0",
		requestTimeout: 30 * time.Second,
	}
	mockPluginCfgIn = pluginCfgIn{
		name:    "mockPlugin",
		pattern: "*",
		version: "1.0.0",
	}
)

type mockValidator struct {
	t   *testing.T
	out *pluginCfgOut
	err error
}

func (m mockValidator) Validate(in pluginCfgIn) (*pluginCfgOut, error) {
	assert.Equal(m.t, mockPluginCfgIn, in)
	return m.out, m.err
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

func Test_register(t *testing.T) {
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
				out, err := r.register(t.Context(), mockPluginCfgIn)
				assert.Nil(t, err)
				assert.Equal(t, mockPluginCfgOut, *out)

				rr := <-chResult
				assert.NoError(t, rr.err)
				assert.Equal(t, mockPluginCfgIn, rr.cfg)

				_, err = r.register(t.Context(), mockPluginCfgIn)
				assert.ErrorContains(t, err, "cannot rerun registration")
			},
		},
		{
			name: "registration gets rejected if validation fails and can't be retried",
			v:    mockValidatorErr(t),
			test: func(t *testing.T, r *registrationLogic, chResult chan registrationResult) {
				_, err := r.register(t.Context(), mockPluginCfgIn)
				assert.ErrorIs(t, err, errMockValidator)

				rr := <-chResult
				assert.ErrorIs(t, rr.err, errMockValidator)

				_, err = r.register(t.Context(), mockPluginCfgIn)
				assert.ErrorContains(t, err, "cannot rerun registration")
			},
		},
		{
			name: "registration does not block but errors if channel is jammed",
			v:    mockValidatorOK(t),
			test: func(t *testing.T, r *registrationLogic, chResult chan registrationResult) {
				chResult <- registrationResult{}

				_, err := r.register(t.Context(), mockPluginCfgIn)
				assert.ErrorContains(t, err, "registration rejected")

				_, err = r.register(t.Context(), mockPluginCfgIn)
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

func (m mockPluginRegistrator) register(_ context.Context, cfg pluginCfgIn) (*pluginCfgOut, error) {
	assert.Equal(m.t, mockPluginCfgIn, cfg)
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
		in   pluginCfgIn
		test func(t *testing.T, resp *connect.Response[resolverv1.RegisterPluginResponse], err error)
	}{
		{
			name: "registration fails",
			r:    mockPluginRegistratorErr(t),
			in:   mockPluginCfgIn,
			test: func(t *testing.T, _ *connect.Response[resolverv1.RegisterPluginResponse], err error) {
				assert.ErrorIs(t, err, errMockRegistrator)
			},
		},
		{
			name: "registration succeeds",
			r:    mockPluginRegistratorOK(t),
			in:   mockPluginCfgIn,
			test: func(t *testing.T, resp *connect.Response[resolverv1.RegisterPluginResponse], err error) {
				assert.NoError(t, err)
				assert.Equal(t, mockPluginCfgOut.engineName, resp.Msg.GetEngineName())
				assert.Equal(t, mockPluginCfgOut.engineVersion, resp.Msg.GetEngineVersion())
				assert.Equal(t, int64(mockPluginCfgOut.requestTimeout.Seconds()), resp.Msg.GetRequestTimeout())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &RegisterService{r: tt.r}
			req := resolverv1.RegisterPluginRequest_builder{
				Name:    proto.String(tt.in.name),
				Version: proto.String(tt.in.version),
				Pattern: proto.String(string(tt.in.pattern)),
			}.Build()
			resp, err := s.RegisterPlugin(t.Context(), connect.NewRequest(req))
			tt.test(t, resp, err)
		})
	}
}
