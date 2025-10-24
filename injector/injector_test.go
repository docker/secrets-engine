package injector

import (
	"context"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/engine"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/telemetry"
	"github.com/docker/secrets-engine/x/testhelper"
)

var (
	mockValidVersion = api.MustNewVersion("v7")
	mockPatternAny   = secrets.MustParsePattern("**")
)

var _ engine.Plugin = &mockInternalPlugin{}

type mockInternalPlugin struct {
	secrets map[secrets.ID]string
}

func (m mockInternalPlugin) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	var result []secrets.Envelope
	for id, v := range m.secrets {
		if pattern.Match(id) {
			result = append(result, secrets.Envelope{ID: id, Value: []byte(v)})
		}
	}
	return result, nil
}

func (m mockInternalPlugin) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func testEngine(t *testing.T) string {
	t.Helper()
	socketPath := testhelper.RandomShortSocketName()
	errEngine := make(chan error)
	up := make(chan struct{})
	go func() {
		errEngine <- engine.Run(t.Context(), "test-engine", "test-version",
			engine.WithLogger(testhelper.TestLogger(t)),
			engine.WithSocketPath(socketPath),
			engine.WithEngineLaunchedPluginsDisabled(),
			engine.WithExternallyLaunchedPluginsDisabled(),
			engine.WithPlugins(map[engine.Config]engine.Plugin{
				{Name: "my-builtin", Version: mockValidVersion, Pattern: mockPatternAny}: &mockInternalPlugin{secrets: map[secrets.ID]string{
					secrets.MustParseID("1password/my-secret"): "some-value",
					secrets.MustParseID("FOO"):                 "bar",
				}},
				{Name: "alphabetic-first-plugin", Version: mockValidVersion, Pattern: mockPatternAny}: &mockInternalPlugin{secrets: map[secrets.ID]string{
					secrets.MustParseID("vault/my-secret"): "some-other-value",
				}},
			}),
			engine.WithAfterHealthyHook(func(context.Context) error {
				close(up)
				return nil
			}),
		)
	}()
	t.Cleanup(func() { assert.NoError(t, testhelper.WaitForErrorWithTimeout(errEngine)) })
	require.NoError(t, testhelper.WaitForClosedWithTimeout(up))
	return socketPath
}

func Test_resolveENV(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		value  string
		result string
		source string
		err    error
	}{
		{
			name: "no value but no secret",
			key:  "GH_TOKEN",
		},
		{
			name:   "no value and secret",
			key:    "FOO",
			result: "bar",
			source: sourceKey,
		},
		{
			name: "no value but invalid key",
			key:  "MY/*/VAR",
		},
		{
			name:   "value but not a secrets engine path",
			key:    "GH_TOKEN",
			value:  "some-value",
			result: "some-value",
		},
		{
			name:  "value but invalid path",
			key:   "GH_TOKEN",
			value: "se://my//path",
			err:   secrets.ErrInvalidPattern,
		},
		{
			name:  "value but no secret",
			key:   "GH_TOKEN",
			value: "se://bar",
			err:   secrets.ErrNotFound,
		},
		{
			name:   "value and first matched secret",
			key:    "GH_TOKEN",
			value:  "se://*/my-secret",
			result: "some-other-value",
			source: sourceValue,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			socketPath := testEngine(t)
			tracker := testhelper.NewTestTracker()
			r, err := newResolver(testhelper.TestLogger(t), tracker, client.WithSocketPath(socketPath))
			require.NoError(t, err)

			value, err := r.resolveENV(t.Context(), tt.key, tt.value)

			if tt.err != nil {
				assert.Empty(t, tracker.GetQueue())
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.result, value)
			if tt.value != value {
				assert.Equal(t, []any{EventSecretsEngineInjectorEnvResolved{Source: tt.source}}, tracker.GetQueue())
			} else {
				assert.Empty(t, tracker.GetQueue())
			}
		})
	}
}

func mockedRewriter(t *testing.T) ContainerCreateRewriter {
	t.Helper()
	return ContainerCreateRewriter{r: &resolver{
		logger: testhelper.TestLogger(t),
		resolver: &mockInternalPlugin{secrets: map[secrets.ID]string{
			secrets.MustParseID("FOO"): "some-value",
			secrets.MustParseID("BAR"): "baz",
		}},
		tracker: telemetry.NoopTracker(),
	}}
}

func Test_ContainerCreateRequestRewrite(t *testing.T) {
	t.Run("no config", func(t *testing.T) {
		r := mockedRewriter(t)
		assert.Nil(t, r.ContainerCreateRequestRewrite(t.Context(), &container.CreateRequest{}))
	})
	t.Run("no errors", func(t *testing.T) {
		r := mockedRewriter(t)
		req := &container.CreateRequest{
			Config: &container.Config{Env: []string{"FOO", "BAZ=se://FOO"}},
		}
		assert.Nil(t, r.ContainerCreateRequestRewrite(t.Context(), req))
		assert.Equal(t, []string{"FOO=some-value", "BAZ=some-value"}, req.Env)
	})
	t.Run("invariant if no secrets", func(t *testing.T) {
		r := mockedRewriter(t)
		req := &container.CreateRequest{
			Config: &container.Config{Env: []string{"something", "GH_TOKEN=", "B*/R", "B/A/R = space before"}},
		}
		assert.Nil(t, r.ContainerCreateRequestRewrite(t.Context(), req))
		assert.Equal(t, []string{"something", "GH_TOKEN=", "B*/R", "B/A/R = space before"}, req.Env)
	})
}
