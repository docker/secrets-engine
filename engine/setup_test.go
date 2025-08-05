package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/internal/api"
	"github.com/docker/secrets-engine/internal/secrets"
)

func Test_newValidatedConfig(t *testing.T) {
	t.Parallel()
	t.Run("name is required", func(t *testing.T) {
		_, err := newValidatedConfig(pluginDataUnvalidated{Version: "foo", Pattern: "*"})
		assert.ErrorIs(t, err, api.ErrEmptyName)
	})
	t.Run("version is required", func(t *testing.T) {
		_, err := newValidatedConfig(pluginDataUnvalidated{Name: "foo", Pattern: "*"})
		assert.ErrorIs(t, err, api.ErrEmptyVersion)
	})
	t.Run("pattern must be valid", func(t *testing.T) {
		_, err := newValidatedConfig(pluginDataUnvalidated{Name: "foo", Version: "v1", Pattern: "*a*"})
		assert.ErrorIs(t, err, secrets.ErrInvalidPattern)
	})
	t.Run("valid data can be compared to be equal", func(t *testing.T) {
		data1, err := newValidatedConfig(pluginDataUnvalidated{Name: "foo", Version: "v1", Pattern: "*"})
		require.NoError(t, err)
		data2, err := newValidatedConfig(pluginDataUnvalidated{Name: "foo", Version: "v1", Pattern: "*"})
		require.NoError(t, err)
		assert.Equal(t, data1, data2)
	})
}
