package stub

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/docker/secrets-engine/pkg/adaptation"
	"github.com/docker/secrets-engine/pkg/api"
	"github.com/docker/secrets-engine/pkg/secrets"
)

type mockPlugin struct {
}

func (m mockPlugin) GetSecret(context.Context, secrets.Request) (secrets.Envelope, error) {
	return secrets.Envelope{}, nil
}

func (m mockPlugin) Shutdown(context.Context) {
}

func Test_newCfg(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "incomplete env based config (secret engine always has to provide all values regardless if they get overwritten by opts)",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_, err := newCfg(mockPlugin{}, WithPluginIdx("10"))
				assert.Error(t, errPluginIdxNotSet, err)
			},
		},
		{
			name: "invalid index from env based config",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_ = os.Setenv(adaptation.PluginIdxEnvVar, "invalid-index")
				_, err := newCfg(mockPlugin{})
				assert.ErrorIs(t, err, &api.ErrInvalidPluginIndex{Actual: "invalid-index", Msg: "must be two digits"})
			},
		},
		{
			name: "invalid duration from env based config",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_ = os.Setenv(adaptation.PluginIdxEnvVar, "10")
				_ = os.Setenv(adaptation.PluginRegistrationTimeoutEnvVar, "10")
				_, err := newCfg(mockPlugin{})
				assert.ErrorContains(t, err, "invalid registration timeout")
			},
		},
		{
			name: "valid env based config",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_ = os.Setenv(adaptation.PluginIdxEnvVar, "10")
				_ = os.Setenv(adaptation.PluginRegistrationTimeoutEnvVar, "10s")
				cfg, err := newCfg(mockPlugin{})
				assert.NoError(t, err)
				assert.Equal(t, "test-plugin", cfg.identity.name)
				assert.Equal(t, "10", cfg.identity.idx)
				assert.Equal(t, 10*time.Second, cfg.registrationTimeout)
			},
		},
		{
			name: "name cannot be overwritten when launched by the secret engine",
			test: func(t *testing.T) {
				defer cleanupEnv()
				_ = os.Setenv(adaptation.PluginNameEnvVar, "test-plugin")
				_ = os.Setenv(adaptation.PluginIdxEnvVar, "10")
				_ = os.Setenv(adaptation.PluginRegistrationTimeoutEnvVar, "10s")
				_, err := newCfg(mockPlugin{}, WithPluginName("name"))
				assert.ErrorContains(t, err, "plugin name already set")
			},
		},
		{
			name: "invalid name opt overwrite",
			test: func(t *testing.T) {
				_, err := newCfg(mockPlugin{}, WithPluginName(""))
				assert.ErrorContains(t, err, "plugin name cannot be empty")
			},
		},
		{
			name: "valid name and index opt overwrite",
			test: func(t *testing.T) {
				cfg, err := newCfg(mockPlugin{}, WithPluginName("new-name"), WithPluginIdx("10"))
				assert.NoError(t, err)
				assert.Equal(t, "new-name", cfg.identity.name)
				assert.Equal(t, "10", cfg.identity.idx)
				assert.Equal(t, adaptation.DefaultPluginRegistrationTimeout, cfg.registrationTimeout)
			},
		},
		{
			name: "invalid index opt overwrite",
			test: func(t *testing.T) {
				_, err := newCfg(mockPlugin{}, WithPluginIdx("invalid-index"))
				assert.ErrorIs(t, err, &api.ErrInvalidPluginIndex{Actual: "invalid-index", Msg: "must be two digits"})
			},
		},
		{
			name: "overwrite socket path",
			test: func(t *testing.T) {
				cfg, err := newCfg(mockPlugin{}, WithPluginName("new-name"), WithPluginIdx("10"), WithSocketPath("/tmp/test.sock"))
				assert.NoError(t, err)
				assert.Equal(t, "/tmp/test.sock", cfg.socketPath)
			},
		},
		{
			name: "overwrite registration timeout",
			test: func(t *testing.T) {
				cfg, err := newCfg(mockPlugin{}, WithPluginName("new-name"), WithPluginIdx("10"), WithRegistrationTimeout(10*adaptation.DefaultPluginRegistrationTimeout))
				assert.NoError(t, err)
				assert.Equal(t, 10*adaptation.DefaultPluginRegistrationTimeout, cfg.registrationTimeout)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

func cleanupEnv() {
	_ = os.Setenv(adaptation.PluginNameEnvVar, "")
	_ = os.Setenv(adaptation.PluginIdxEnvVar, "")
	_ = os.Setenv(adaptation.PluginRegistrationTimeoutEnvVar, "")
}

func Test_complementIdentity(t *testing.T) {
	tests := []struct {
		name     string
		identity identity
		expected identity
		args     []string
		err      error
	}{
		{
			name: "valid identity",
			identity: identity{
				name: "test-plugin",
				idx:  "10",
			},
			expected: identity{
				name: "test-plugin",
				idx:  "10",
			},
		},
		{
			name: "missing name pulled from args",
			identity: identity{
				idx: "10",
			},
			args: []string{"test-plugin"},
			expected: identity{
				name: "test-plugin",
				idx:  "10",
			},
		},
		{
			name: "invalid identity pulled from args",
			args: []string{"test-plugin"},
			err:  &api.ErrInvalidPluginIndex{Actual: "test", Msg: "must be two digits"},
		},
		{
			name: "identity pulled from args",
			args: []string{"10-test-plugin"},
			expected: identity{
				name: "test-plugin",
				idx:  "10",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args != nil {
				var args []string
				copy(args, os.Args)
				defer func() {
					os.Args = args
				}()
				os.Args = tt.args
			}
			i, err := complementIdentity(tt.identity)
			if tt.err != nil {
				assert.ErrorIs(t, err, tt.err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, *i)
		})
	}
}
