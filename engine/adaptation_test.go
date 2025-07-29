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
	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/internal/testhelper"
	"github.com/docker/secrets-engine/internal/testhelper/dummy"
	p "github.com/docker/secrets-engine/plugin"
)

func Test_SecretsEngine(t *testing.T) {
	t.Parallel()
	dir := dummy.CreateDummyPlugins(t, dummy.Plugins{Plugins: []dummy.PluginBehaviour{{Value: "foo"}, {Value: "bar"}}})
	socketPath := filepath.Join(t.TempDir(), "test.sock")
	pattern, err := secrets.ParsePattern("*")
	require.NoError(t, err)
	id, err := secrets.NewID("my-secret")
	require.NoError(t, err)
	e, err := New("test-engine", "test-version",
		WithSocketPath(socketPath),
		WithPluginPath(dir),
		WithPlugins(map[string]Plugin{"my-builtin": &mockInternalPlugin{pattern: pattern, secrets: map[string]string{id.String(): "some-value"}}}))
	assert.NoError(t, err)
	runEngineAsync(t, e)
	assert.ErrorContains(t, e.Run(t.Context()), "already started")
	c, err := client.New(client.WithSocketPath(socketPath))
	require.NoError(t, err)

	t.Run("unique existing secrets across all plugin types", func(t *testing.T) {
		t.Parallel()
		t.Run("engine launched plugins", func(t *testing.T) {
			id, err := secrets.NewID("foo")
			require.NoError(t, err)
			foo, err := c.GetSecret(t.Context(), secrets.Request{ID: id})
			require.NoError(t, err)
			assert.Equal(t, "foo", foo.ID.String())
			assert.Equal(t, "foo-value", string(foo.Value))
			assert.Equal(t, "plugin-foo", foo.Provider)
			assert.Empty(t, foo.Error)
			assert.NotEmpty(t, foo.ResolvedAt)
			assert.NotEmpty(t, foo.CreatedAt)
			assert.NotEmpty(t, foo.ExpiresAt)
			bar, err := c.GetSecret(t.Context(), secrets.Request{ID: secrets.MustNewID("bar")})
			require.NoError(t, err)
			assert.Equal(t, "bar", bar.ID.String())
			assert.Equal(t, "bar-value", string(bar.Value))
		})
		t.Run("internal plugin", func(t *testing.T) {
			mySecret, err := c.GetSecret(t.Context(), secrets.Request{ID: secrets.MustNewID("my-secret")})
			require.NoError(t, err)
			assert.Equal(t, "my-secret", mySecret.ID.String())
			assert.Equal(t, "some-value", string(mySecret.Value))
			assert.Equal(t, "my-builtin", mySecret.Provider)
		})
		t.Run("externally launched plugins", func(t *testing.T) {
			shutdown1 := launchExternalPlugin(t, externalPluginTestConfig{
				socketPath: socketPath,
				name:       "my-plugin",
				pattern:    secrets.MustParsePattern("special/*"),
				id:         secrets.MustNewID("special/secret"),
			})
			assert.EventuallyWithT(t, func(collect *assert.CollectT) {
				secret, err := c.GetSecret(t.Context(), secrets.Request{ID: secrets.MustNewID("special/secret")})
				require.NoError(collect, err)
				assert.Equal(collect, secrets.MustNewID("special/secret"), secret.ID)
				assert.Equal(collect, mockSecretValue, string(secret.Value))
				assert.Equal(t, "my-plugin", secret.Provider)
			}, 2*time.Second, 100*time.Millisecond)
			shutdown2 := launchExternalPlugin(t, externalPluginTestConfig{
				socketPath: socketPath,
				name:       "3rd-party-plugin",
				pattern:    secrets.MustParsePattern("**"),
				id:         secrets.MustNewID("3rd-party-vendor/foo"),
			})
			assert.EventuallyWithT(t, func(collect *assert.CollectT) {
				secret, err := c.GetSecret(t.Context(), secrets.Request{ID: secrets.MustNewID("3rd-party-vendor/foo")})
				require.NoError(collect, err)
				assert.Equal(collect, "3rd-party-vendor/foo", secret.ID.String())
				assert.Equal(collect, mockSecretValue, string(secret.Value))
				assert.Equal(t, "3rd-party-plugin", secret.Provider)
			}, 2*time.Second, 100*time.Millisecond)
			shutdown1()
			_, err = c.GetSecret(t.Context(), secrets.Request{ID: secrets.MustNewID("special/secret")})
			require.Error(t, err)
			shutdown2()
			_, err = c.GetSecret(t.Context(), secrets.Request{ID: secrets.MustNewID("3rd-party-vendor/foo")})
			require.Error(t, err)
		})
	})
	t.Run("non existing secrets", func(t *testing.T) {
		secret, err := c.GetSecret(t.Context(), secrets.Request{ID: secrets.MustNewID("fancy-secret")})
		require.Error(t, err)
		assert.ErrorContains(t, err, "secret not found")
		assert.Contains(t, secret.Error, "secret not found")
	})
	t.Run("non-unique secrets", func(t *testing.T) {
		mockFromFoo, err := c.GetSecret(t.Context(), secrets.Request{ID: dummy.MockSecretID, Provider: "plugin-foo"})
		require.NoError(t, err)
		assert.Equal(t, dummy.MockSecretID.String(), mockFromFoo.ID.String())
		assert.Equal(t, dummy.MockSecretValue, string(mockFromFoo.Value))
		assert.Equal(t, "plugin-foo", mockFromFoo.Provider)
		mockFromBar, err := c.GetSecret(t.Context(), secrets.Request{ID: dummy.MockSecretID, Provider: "plugin-bar"})
		require.NoError(t, err)
		assert.Equal(t, dummy.MockSecretID.String(), mockFromBar.ID.String())
		assert.Equal(t, dummy.MockSecretValue, string(mockFromBar.Value))
		assert.Equal(t, "plugin-bar", mockFromBar.Provider)
	})
	t.Run("existing secrets but wrong provider", func(t *testing.T) {
		_, err := c.GetSecret(t.Context(), secrets.Request{ID: secrets.MustNewID("foo"), Provider: "plugin-bar"})
		require.Error(t, err)
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
	require.NoError(t, err)
	runEngineAsync(t, e)

	conn, err := net.Dial("unix", path)
	require.NoError(t, err)
	plugin := newMockedPlugin()
	_, err = p.New(plugin, p.WithPluginName("my-plugin"), p.WithConnection(conn))
	require.Error(t, err)
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
				WithPlugins(map[string]Plugin{
					"my-builtin": &mockInternalPlugin{
						pattern: secrets.MustParsePattern("*"),
						secrets: map[string]string{"my-secret": "some-value"},
					},
				}),
			}
			if test.extraOption != nil {
				options = append(options, test.extraOption)
			}
			e, err := New("test-engine", "test-version", options...)
			require.NoError(t, err)
			runEngineAsync(t, e)
			c, err := client.New(client.WithSocketPath(socketPath))
			require.NoError(t, err)
			_, err = c.GetSecret(t.Context(), secrets.Request{
				ID: secrets.MustNewID("foo"),
			})
			if test.shouldGetSecretFromExternalPlugin {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			mySecret, err := c.GetSecret(t.Context(), secrets.Request{
				ID: secrets.MustNewID("my-secret"),
			})
			require.NoError(t, err)
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
	pattern    secrets.Pattern
	id         secrets.ID
}

func launchExternalPlugin(t *testing.T, cfg externalPluginTestConfig) func() {
	t.Helper()
	conn, err := net.Dial("unix", cfg.socketPath)
	require.NoError(t, err)
	plugin := newMockedPlugin(WithPattern(cfg.pattern), WithID(cfg.id))
	s, err := p.New(plugin, p.WithPluginName(cfg.name), p.WithConnection(conn))
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
