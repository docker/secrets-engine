package engine

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/internal/secrets"
)

func Test_SecretsEngine(t *testing.T) {
	t.Parallel()
	okPlugins := []string{"plugin-foo", "plugin-bar"}
	dir := createDummyPlugins(t, dummyPlugins{okPlugins: okPlugins})
	socketPath := filepath.Join(t.TempDir(), "test.sock")
	e, err := New("test-engine", "test-version",
		WithSocketPath(socketPath),
		WithPluginPath(dir),
		WithPlugins(map[string]Plugin{"my-builtin": &mockInternalPlugin{pattern: "*", secrets: map[secrets.ID]string{"my-secret": "some-value"}}}))
	assert.NoError(t, err)
	require.NoError(t, e.Start())
	t.Cleanup(func() { assert.NoError(t, e.Stop()) })
	c, err := client.New(client.WithSocketPath(socketPath))
	require.NoError(t, err)

	t.Run("unique existing secrets (internal and external plugins)", func(t *testing.T) {
		foo, err := c.GetSecret(t.Context(), secrets.Request{ID: "foo"})
		assert.NoError(t, err)
		assert.Equal(t, secrets.ID("foo"), foo.ID)
		assert.Equal(t, "foo-value", string(foo.Value))
		assert.Equal(t, "plugin-foo", foo.Provider)
		assert.Empty(t, foo.Error)
		assert.NotEmpty(t, foo.ResolvedAt)
		assert.NotEmpty(t, foo.CreatedAt)
		assert.NotEmpty(t, foo.ExpiresAt)
		bar, err := c.GetSecret(t.Context(), secrets.Request{ID: "bar"})
		assert.NoError(t, err)
		assert.Equal(t, secrets.ID("bar"), bar.ID)
		assert.Equal(t, "bar-value", string(bar.Value))
		mySecret, err := c.GetSecret(t.Context(), secrets.Request{ID: "my-secret"})
		assert.NoError(t, err)
		assert.Equal(t, secrets.ID("my-secret"), mySecret.ID)
		assert.Equal(t, "some-value", string(mySecret.Value))
		assert.Equal(t, "my-builtin", mySecret.Provider)
	})
	t.Run("non existing secrets", func(t *testing.T) {
		secret, err := c.GetSecret(t.Context(), secrets.Request{ID: "fancy-secret"})
		assert.ErrorContains(t, err, "secret not found")
		assert.Contains(t, secret.Error, "secret not found")
	})
	t.Run("non-unique secrets", func(t *testing.T) {
		mockFromFoo, err := c.GetSecret(t.Context(), secrets.Request{ID: mockSecretID, Provider: "plugin-foo"})
		assert.NoError(t, err)
		assert.Equal(t, mockSecretID, mockFromFoo.ID)
		assert.Equal(t, mockSecretValue, string(mockFromFoo.Value))
		assert.Equal(t, "plugin-foo", mockFromFoo.Provider)
		mockFromBar, err := c.GetSecret(t.Context(), secrets.Request{ID: mockSecretID, Provider: "plugin-bar"})
		assert.NoError(t, err)
		assert.Equal(t, mockSecretID, mockFromBar.ID)
		assert.Equal(t, mockSecretValue, string(mockFromBar.Value))
		assert.Equal(t, "plugin-bar", mockFromBar.Provider)
	})
	t.Run("existing secrets but wrong provider", func(t *testing.T) {
		_, err := c.GetSecret(t.Context(), secrets.Request{ID: "foo", Provider: "plugin-bar"})
		assert.ErrorContains(t, err, "secret not found")
	})
}
