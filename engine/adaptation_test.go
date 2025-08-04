package engine

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/internal/api"
	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/internal/testhelper"
	"github.com/docker/secrets-engine/internal/testhelper/dummy"
	p "github.com/docker/secrets-engine/plugin"
)

var mockValidVersion = api.MustNewVersion("7")

func Test_SecretsEngine(t *testing.T) {
	t.Parallel()
	dir := dummy.CreateDummyPlugins(t, dummy.Plugins{Plugins: []dummy.PluginBehaviour{{Value: "foo"}, {Value: "bar"}}})
	socketPath := filepath.Join(t.TempDir(), "test.sock")
	e, err := New("test-engine", "test-version",
		WithSocketPath(socketPath),
		WithPluginPath(dir),
		WithPlugins(map[Config]Plugin{{"my-builtin", mockValidVersion, "*"}: &mockInternalPlugin{secrets: map[string]string{"my-secret": "some-value"}}}))
	assert.NoError(t, err)
	runEngineAsync(t, e)
	assert.ErrorContains(t, e.Run(t.Context()), "already started")
	c, err := client.New(client.WithSocketPath(socketPath))
	require.NoError(t, err)

	t.Run("unique existing secrets across all plugin types", func(t *testing.T) {
		t.Parallel()
		t.Run("engine launched plugins", func(t *testing.T) {
			foo, err := c.GetSecret(t.Context(), secrets.Request{ID: "foo"})
			assert.NoError(t, err)
			assert.Equal(t, "foo", foo.ID.String())
			assert.Equal(t, "foo-value", string(foo.Value))
			assert.Equal(t, "plugin-foo", foo.Provider)
			assert.Empty(t, foo.Error)
			assert.NotEmpty(t, foo.ResolvedAt)
			assert.NotEmpty(t, foo.CreatedAt)
			assert.NotEmpty(t, foo.ExpiresAt)
			bar, err := c.GetSecret(t.Context(), secrets.Request{ID: "bar"})
			assert.NoError(t, err)
			assert.Equal(t, "bar", bar.ID.String())
			assert.Equal(t, "bar-value", string(bar.Value))
		})
		t.Run("internal plugin", func(t *testing.T) {
			mySecret, err := c.GetSecret(t.Context(), secrets.Request{ID: "my-secret"})
			assert.NoError(t, err)
			assert.Equal(t, "my-secret", mySecret.ID.String())
			assert.Equal(t, "some-value", string(mySecret.Value))
			assert.Equal(t, "my-builtin", mySecret.Provider)
		})
		t.Run("externally launched plugins", func(t *testing.T) {
			shutdown1 := launchExternalPlugin(t, externalPluginTestConfig{
				socketPath: socketPath,
				name:       "my-plugin",
				pattern:    secrets.MustParsePatternNew("special/*"),
				id:         secrets.MustParseIDNew("special/secret"),
			})
			assert.EventuallyWithT(t, func(collect *assert.CollectT) {
				secret, err := c.GetSecret(t.Context(), secrets.Request{ID: "special/secret"})
				assert.NoError(collect, err)
				assert.Equal(collect, "special/secret", secret.ID.String())
				assert.Equal(collect, mockSecretValue, string(secret.Value))
				assert.Equal(t, "my-plugin", secret.Provider)
			}, 2*time.Second, 100*time.Millisecond)
			shutdown2 := launchExternalPlugin(t, externalPluginTestConfig{
				socketPath: socketPath,
				name:       "3rd-party-plugin",
				pattern:    secrets.MustParsePatternNew("**"),
				id:         secrets.MustParseIDNew("3rd-party-vendor/foo"),
			})
			assert.EventuallyWithT(t, func(collect *assert.CollectT) {
				secret, err := c.GetSecret(t.Context(), secrets.Request{ID: "3rd-party-vendor/foo"})
				assert.NoError(collect, err)
				assert.Equal(collect, "3rd-party-vendor/foo", secret.ID.String())
				assert.Equal(collect, mockSecretValue, string(secret.Value))
				assert.Equal(t, "3rd-party-plugin", secret.Provider)
			}, 2*time.Second, 100*time.Millisecond)
			shutdown1()
			_, err = c.GetSecret(t.Context(), secrets.Request{ID: "special/secret"})
			assert.Error(t, err)
			shutdown2()
			_, err = c.GetSecret(t.Context(), secrets.Request{ID: "3rd-party-vendor/foo"})
			assert.Error(t, err)
		})
	})
	t.Run("non existing secrets", func(t *testing.T) {
		secret, err := c.GetSecret(t.Context(), secrets.Request{ID: "fancy-secret"})
		assert.ErrorContains(t, err, "secret not found")
		assert.Contains(t, secret.Error, "secret not found")
	})
	t.Run("non-unique secrets", func(t *testing.T) {
		mockFromFoo, err := c.GetSecret(t.Context(), secrets.Request{ID: dummy.MockSecretID, Provider: "plugin-foo"})
		assert.NoError(t, err)
		assert.Equal(t, dummy.MockSecretID, mockFromFoo.ID)
		assert.Equal(t, dummy.MockSecretValue, string(mockFromFoo.Value))
		assert.Equal(t, "plugin-foo", mockFromFoo.Provider)
		mockFromBar, err := c.GetSecret(t.Context(), secrets.Request{ID: dummy.MockSecretID, Provider: "plugin-bar"})
		assert.NoError(t, err)
		assert.Equal(t, dummy.MockSecretID, mockFromBar.ID)
		assert.Equal(t, dummy.MockSecretValue, string(mockFromBar.Value))
		assert.Equal(t, "plugin-bar", mockFromBar.Provider)
	})
	t.Run("existing secrets but wrong provider", func(t *testing.T) {
		_, err := c.GetSecret(t.Context(), secrets.Request{ID: "foo", Provider: "plugin-bar"})
		assert.ErrorContains(t, err, "secret not found")
	})
}

func TestWithDynamicPluginsDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.sock")
	e, err := New("test-engine", "test-version",
		WithSocketPath(path),
		WithPluginPath(t.TempDir()),
		WithExternallyLaunchedPluginsDisabled(),
	)
	assert.NoError(t, err)
	runEngineAsync(t, e)

	conn, err := net.Dial("unix", path)
	require.NoError(t, err)
	plugin := newMockedPlugin()
	_, err = p.New(plugin, p.Config{Version: mockValidVersion, Pattern: secrets.MustParsePatternNew("*")}, p.WithPluginName("my-plugin"), p.WithConnection(conn))
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
			dir := dummy.CreateDummyPlugins(t, dummy.Plugins{Plugins: []dummy.PluginBehaviour{{Value: "foo"}}})
			socketPath := testhelper.RandomShortSocketName()
			options := []Option{
				WithSocketPath(socketPath),
				WithPluginPath(dir),
				WithExternallyLaunchedPluginsDisabled(),
				WithPlugins(map[Config]Plugin{{"my-builtin", mockValidVersion, "*"}: &mockInternalPlugin{secrets: map[string]string{"my-secret": "some-value"}}}),
			}
			if test.extraOption != nil {
				options = append(options, test.extraOption)
			}
			e, err := New("test-engine", "test-version", options...)
			assert.NoError(t, err)
			runEngineAsync(t, e)
			c, err := client.New(client.WithSocketPath(socketPath))
			require.NoError(t, err)
			_, err = c.GetSecret(t.Context(), secrets.Request{ID: "foo"})
			if test.shouldGetSecretFromExternalPlugin {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
			mySecret, err := c.GetSecret(t.Context(), secrets.Request{ID: "my-secret"})
			assert.NoError(t, err)
			assert.Equal(t, "my-secret", mySecret.ID.String())
			assert.Equal(t, "some-value", string(mySecret.Value))
			assert.Equal(t, "my-builtin", mySecret.Provider)
		})
	}
}

func runEngineAsync(t *testing.T, e Engine) {
	t.Helper()
	errEngine := make(chan error)
	done := make(chan struct{})
	go func() {
		errEngine <- e.Run(t.Context(), func() { close(done) })
	}()
	assert.NoError(t, testhelper.WaitForClosedWithTimeout(done))
	t.Cleanup(func() { assert.NoError(t, testhelper.WaitForErrorWithTimeout(errEngine)) })
}

type externalPluginTestConfig struct {
	socketPath string
	name       string
	pattern    secrets.PatternNew
	id         secrets.IDNew
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
