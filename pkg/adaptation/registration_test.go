package adaptation

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	errMockValidator = errors.New("mockValidatorErr")

	mockPluginCfgOut = pluginCfgOut{
		config:        "mockConfig",
		engineName:    "mockEngine",
		engineVersion: "1.0.0",
	}
	mockPluginCfgIn = pluginCfgIn{
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
