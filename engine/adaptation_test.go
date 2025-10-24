package engine

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/engine/internal/testdummy"
	p "github.com/docker/secrets-engine/plugin"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

var (
	mockValidVersion = api.MustNewVersion("v7")
	mockPatternAny   = secrets.MustParsePattern("*")
)

func testEngine(t *testing.T) (secrets.Resolver, string) {
	t.Helper()
	dir := testdummy.CreateDummyPlugins(t, testdummy.Plugins{Plugins: []testdummy.PluginBehaviour{{Value: "foo"}, {Value: "bar"}}})
	socketPath := testhelper.RandomShortSocketName()
	runEngineAsync(t, "test-engine", "test-version",
		WithLogger(testhelper.TestLogger(t)),
		WithSocketPath(socketPath),
		WithPluginPath(dir),
		WithPlugins(map[Config]Plugin{
			{"my-builtin", mockValidVersion, mockPatternAny}: &mockInternalPlugin{secrets: map[secrets.ID]string{secrets.MustParseID("my-secret"): "some-value"}},
		}),
	)
	c, err := client.New(client.WithSocketPath(socketPath))
	require.NoError(t, err)
	return c, socketPath
}

func Test_SecretsEngine(t *testing.T) {
	t.Parallel()

	t.Run("unique existing secrets across all plugin types", func(t *testing.T) {
		t.Parallel()
		t.Run("engine launched plugins", func(t *testing.T) {
			c, _ := testEngine(t)
			foo, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("foo"))
			require.NoError(t, err)
			require.NotEmpty(t, foo)
			assert.Equal(t, "foo", foo[0].ID.String())
			assert.Equal(t, "foo-value", string(foo[0].Value))
			assert.Equal(t, "plugin-foo", foo[0].Provider)
			assert.NotEmpty(t, foo[0].ResolvedAt)
			assert.NotEmpty(t, foo[0].CreatedAt)
			assert.NotEmpty(t, foo[0].ExpiresAt)
			bar, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("bar"))
			require.NoError(t, err)
			require.NotEmpty(t, bar)
			assert.Equal(t, "bar", bar[0].ID.String())
			assert.Equal(t, "bar-value", string(bar[0].Value))
		})
		t.Run("internal plugin", func(t *testing.T) {
			c, _ := testEngine(t)
			mySecret, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("my-secret"))
			require.NoError(t, err)
			require.NotEmpty(t, mySecret)
			assert.Equal(t, "my-secret", mySecret[0].ID.String())
			assert.Equal(t, "some-value", string(mySecret[0].Value))
			assert.Equal(t, "my-builtin", mySecret[0].Provider)
		})
		t.Run("externally launched plugins", func(t *testing.T) {
			c, socketPath := testEngine(t)
			shutdown1 := launchExternalPlugin(t, externalPluginTestConfig{
				socketPath: socketPath,
				name:       "my-plugin",
				pattern:    secrets.MustParsePattern("special/*"),
				id:         secrets.MustParseID("special/secret"),
			})
			assert.EventuallyWithT(t, func(collect *assert.CollectT) {
				secret, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("special/secret"))
				require.NoError(collect, err)
				require.NotEmpty(t, secret)
				assert.Equal(collect, "special/secret", secret[0].ID.String())
				assert.Equal(collect, mockSecretValue, string(secret[0].Value))
				assert.Equal(t, "my-plugin", secret[0].Provider)
			}, 2*time.Second, 100*time.Millisecond)
			shutdown2 := launchExternalPlugin(t, externalPluginTestConfig{
				socketPath: socketPath,
				name:       "3rd-party-plugin",
				pattern:    secrets.MustParsePattern("**"),
				id:         secrets.MustParseID("3rd-party-vendor/foo"),
			})
			assert.EventuallyWithT(t, func(collect *assert.CollectT) {
				secret, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("3rd-party-vendor/foo"))
				require.NoError(collect, err)
				require.NotEmpty(t, secret)
				assert.Equal(collect, "3rd-party-vendor/foo", secret[0].ID.String())
				assert.Equal(collect, mockSecretValue, string(secret[0].Value))
				assert.Equal(t, "3rd-party-plugin", secret[0].Provider)
			}, 2*time.Second, 100*time.Millisecond)
			shutdown1()
			_, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("special/secret"))
			assert.Error(t, err)
			shutdown2()
			_, err = c.GetSecrets(t.Context(), secrets.MustParsePattern("3rd-party-vendor/foo"))
			assert.Error(t, err)
		})
	})
	t.Run("non existing secrets", func(t *testing.T) {
		c, _ := testEngine(t)
		_, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("fancy-secret"))
		assert.ErrorIs(t, err, secrets.ErrNotFound)
	})
	t.Run("non-unique secrets", func(t *testing.T) {
		c, _ := testEngine(t)
		envelopes, err := c.GetSecrets(t.Context(), testdummy.MockSecretPattern)
		assert.NoError(t, err)
		require.Len(t, envelopes, 2)
		assert.Equal(t, testdummy.MockSecretID.String(), envelopes[0].ID.String())
		assert.Equal(t, testdummy.MockSecretValue, string(envelopes[0].Value))
		assert.Equal(t, "plugin-bar", envelopes[0].Provider)
		assert.Equal(t, testdummy.MockSecretID.String(), envelopes[1].ID.String())
		assert.Equal(t, testdummy.MockSecretValue, string(envelopes[1].Value))
		assert.Equal(t, "plugin-foo", envelopes[1].Provider)
	})
}

func TestWithDynamicPluginsDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.sock")
	runEngineAsync(t, "test-engine", "test-version",
		WithSocketPath(path),
		WithPluginPath(t.TempDir()),
		WithExternallyLaunchedPluginsDisabled(),
	)

	conn, err := net.Dial("unix", path)
	require.NoError(t, err)
	plugin := newMockedPlugin()
	_, err = p.New(plugin, p.Config{Version: mockValidVersion, Pattern: secrets.MustParsePattern("*")}, p.WithPluginName("my-plugin"), p.WithConnection(conn))
	assert.ErrorContains(t, err, "external plugin rejected")
}

func TestWithEnginePluginsDisabled(t *testing.T) {
	tests := []struct {
		name                              string
		shouldGetSecretFromExternalPlugin bool
		extraOption                       Option
	}{
		{
			name:                              "external plugins enabled",
			shouldGetSecretFromExternalPlugin: true,
		},
		{
			name:        "external plugins disabled",
			extraOption: WithEngineLaunchedPluginsDisabled(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := testdummy.CreateDummyPlugins(t, testdummy.Plugins{Plugins: []testdummy.PluginBehaviour{{Value: "foo"}}})
			socketPath := testhelper.RandomShortSocketName()
			options := []Option{
				WithSocketPath(socketPath),
				WithPluginPath(dir),
				WithExternallyLaunchedPluginsDisabled(),
				WithPlugins(map[Config]Plugin{
					{"my-builtin", mockValidVersion, mockPatternAny}: &mockInternalPlugin{secrets: map[secrets.ID]string{secrets.MustParseID("my-secret"): "some-value"}},
				}),
			}
			if test.extraOption != nil {
				options = append(options, test.extraOption)
			}
			runEngineAsync(t, "test-engine", "test-version", options...)
			c, err := client.New(client.WithSocketPath(socketPath))
			require.NoError(t, err)
			_, err = c.GetSecrets(t.Context(), secrets.MustParsePattern("foo"))
			if test.shouldGetSecretFromExternalPlugin {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
			mySecret, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("my-secret"))
			require.NoError(t, err)
			require.NotEmpty(t, mySecret)
			assert.Equal(t, "my-secret", mySecret[0].ID.String())
			assert.Equal(t, "some-value", string(mySecret[0].Value))
			assert.Equal(t, "my-builtin", mySecret[0].Provider)
		})
	}
}

func TestTelemetry(t *testing.T) {
	spanRecorder, _ := testhelper.SetupTelemetry(t)

	socketPath := testhelper.RandomShortSocketName()
	errEngine := make(chan error)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tracker := testhelper.NewTestTracker()
	go func() {
		errEngine <- Run(ctx, "test-engine", "test-version",
			WithSocketPath(socketPath),
			WithExternallyLaunchedPluginsDisabled(),
			WithEngineLaunchedPluginsDisabled(),
			WithAfterHealthyHook(func(context.Context) error {
				close(done)
				return nil
			}),
			WithTracker(tracker),
		)
	}()
	assert.NoError(t, testhelper.WaitForClosedWithTimeout(done))
	cancel()
	assert.NoError(t, filterYamuxErrors(testhelper.WaitForErrorWithTimeout(errEngine)))

	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	recordedSpan := spans[0]
	assert.Equal(t, "engine.run", recordedSpan.Name())
	assert.Equal(t, []string{"ready", "shutdown"}, toEventNames(recordedSpan.Events()))
	assert.Equal(t, codes.Ok, recordedSpan.Status().Code)
	assert.Equal(t, []any{EventSecretsEngineStarted{}}, tracker.GetQueue())
}

func toEventNames(events []trace.Event) []string {
	var names []string
	for _, event := range events {
		names = append(names, event.Name)
	}
	return names
}

func runEngineAsync(t *testing.T, name, version string, opts ...Option) {
	t.Helper()
	errEngine := make(chan error)
	done := make(chan struct{})
	opts = append(opts, WithAfterHealthyHook(func(context.Context) error {
		close(done)
		return nil
	}))
	go func() {
		errEngine <- Run(t.Context(), name, version, opts...)
	}()
	assert.NoError(t, testhelper.WaitForClosedWithTimeout(done))

	// TODO: https://github.com/docker/secrets-engine/issues/316
	// We occasionally get "unavailable: remote end is not accepting connections"
	// and "unavailable: session shutdown" here.
	t.Cleanup(func() { assert.NoError(t, filterYamuxErrors(testhelper.WaitForErrorWithTimeout(errEngine))) })
}

// TODO: https://github.com/docker/secrets-engine/issues/316
// Move this down the chain to the appropriate place in the IPC stack.
func filterYamuxErrors(err error) error {
	if errors.Is(err, yamux.ErrSessionShutdown) {
		return nil
	}
	if errors.Is(err, yamux.ErrRemoteGoAway) {
		return nil
	}
	return err
}

type externalPluginTestConfig struct {
	socketPath string
	name       string
	pattern    secrets.Pattern
	id         secrets.ID
}

func launchExternalPlugin(t *testing.T, cfg externalPluginTestConfig) func() {
	t.Helper()
	conn, err := net.Dial("unix", cfg.socketPath)
	require.NoError(t, err)
	plugin := newMockedPlugin(WithID(cfg.id))
	s, err := p.New(plugin, p.Config{Version: mockValidVersion, Pattern: cfg.pattern, Logger: testhelper.TestLogger(t)}, p.WithPluginName(cfg.name), p.WithConnection(conn))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error)
	go func() {
		runErr <- s.Run(ctx)
	}()
	return func() {
		t.Helper()
		cancel()
		select {
		case err := <-runErr:
			assert.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Fatal("external plugin did not shutdown after timeout")
		}
	}
}
