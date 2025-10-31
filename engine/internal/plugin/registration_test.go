package plugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/testhelper"
)

var (
	errMockValidator   = errors.New("mockValidatorErr")
	errMockRegistrator = errors.New("mockRegistratorErr")

	mockPluginCfgOut = ConfigOut{
		EngineName:     "mockEngine",
		EngineVersion:  "v1.0.0",
		RequestTimeout: 30 * time.Second,
	}
	mockPluginCfgInUnvalidated = Unvalidated{
		Name:    "mockPlugin",
		Pattern: "*",
		Version: "v1.0.0",
	}
	mockPluginCfgIn = mustNewValidatedConfig(mockPluginCfgInUnvalidated)
)

func mustNewValidatedConfig(in Unvalidated) Metadata {
	r, err := NewValidatedConfig(in)
	if err != nil {
		panic(err)
	}
	return r
}

type mockValidator struct {
	t   *testing.T
	out *ConfigOut
	err error
}

func (m mockValidator) Validate(in Unvalidated) (Metadata, *ConfigOut, error) {
	assert.Equal(m.t, mockPluginCfgInUnvalidated, in)
	return mockPluginCfgIn, m.out, m.err
}

func mockValidatorOK(t *testing.T) ConfigValidator {
	return mockValidator{
		t:   t,
		out: &mockPluginCfgOut,
	}
}

func mockValidatorErr(t *testing.T) ConfigValidator {
	return mockValidator{
		t:   t,
		err: errMockValidator,
	}
}

func Test_registration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		v    ConfigValidator
		test func(t *testing.T, r *registrationLogic, chResult chan RegistrationResult)
	}{
		{
			name: "can only register once",
			v:    mockValidatorOK(t),
			test: func(t *testing.T, r *registrationLogic, chResult chan RegistrationResult) {
				out, err := r.Register(t.Context(), mockPluginCfgInUnvalidated)
				assert.Nil(t, err)
				assert.Equal(t, mockPluginCfgOut, *out)

				rr := <-chResult
				require.NoError(t, rr.Err)
				assert.Equal(t, mockPluginCfgIn, rr.Config)

				_, err = r.Register(t.Context(), mockPluginCfgInUnvalidated)
				assert.ErrorContains(t, err, "cannot rerun registration")
			},
		},
		{
			name: "registration gets rejected if validation fails and can't be retried",
			v:    mockValidatorErr(t),
			test: func(t *testing.T, r *registrationLogic, chResult chan RegistrationResult) {
				_, err := r.Register(t.Context(), mockPluginCfgInUnvalidated)
				assert.ErrorIs(t, err, errMockValidator)

				rr := <-chResult
				assert.ErrorIs(t, rr.Err, errMockValidator)

				_, err = r.Register(t.Context(), mockPluginCfgInUnvalidated)
				assert.ErrorContains(t, err, "cannot rerun registration")
			},
		},
		{
			name: "registration does not block but errors if channel is jammed",
			v:    mockValidatorOK(t),
			test: func(t *testing.T, r *registrationLogic, chResult chan RegistrationResult) {
				chResult <- RegistrationResult{}

				_, err := r.Register(t.Context(), mockPluginCfgInUnvalidated)
				assert.ErrorContains(t, err, "registration rejected")

				_, err = r.Register(t.Context(), mockPluginCfgInUnvalidated)
				assert.ErrorContains(t, err, "cannot rerun registration")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := make(chan RegistrationResult, 1)
			r := NewRegistrationLogic(tt.v, c)
			tt.test(t, r.(*registrationLogic), c)
		})
	}
}

type mockPluginRegistrator struct {
	t   *testing.T
	out *ConfigOut
	err error
}

func (m mockPluginRegistrator) Register(_ context.Context, cfg Unvalidated) (*ConfigOut, error) {
	assert.Equal(m.t, mockPluginCfgInUnvalidated, cfg)
	return m.out, m.err
}

func mockPluginRegistratorOK(t *testing.T) Registrator {
	return mockPluginRegistrator{
		t:   t,
		out: &mockPluginCfgOut,
	}
}

func mockPluginRegistratorErr(t *testing.T) Registrator {
	return mockPluginRegistrator{
		t:   t,
		err: errMockRegistrator,
	}
}

func Test_RegisterPlugin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    Registrator
		in   Unvalidated
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
				assert.Equal(t, mockPluginCfgOut.EngineName, resp.Msg.GetEngineName())
				assert.Equal(t, mockPluginCfgOut.EngineVersion, resp.Msg.GetEngineVersion())
				assert.Equal(t, mockPluginCfgOut.RequestTimeout, resp.Msg.GetRequestTimeout().AsDuration())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &RegisterService{Logger: testhelper.TestLogger(t), PluginRegistrator: tt.r}
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
