package runtime

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/runtime/internal/plugin"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

func Test_newValidatedConfig(t *testing.T) {
	t.Parallel()
	t.Run("name is required", func(t *testing.T) {
		_, err := plugin.NewValidatedConfig(plugin.Unvalidated{Version: "foo", Pattern: "*"})
		assert.ErrorIs(t, err, api.ErrEmptyName)
	})
	t.Run("version is required", func(t *testing.T) {
		_, err := plugin.NewValidatedConfig(plugin.Unvalidated{Name: "foo", Pattern: "*"})
		assert.ErrorIs(t, err, api.ErrEmptyVersion)
	})
	t.Run("pattern must be valid", func(t *testing.T) {
		_, err := plugin.NewValidatedConfig(plugin.Unvalidated{Name: "foo", Version: "v1", Pattern: "*a*"})
		assert.ErrorIs(t, err, secrets.ErrInvalidPattern)
	})
	t.Run("valid data can be compared to be equal", func(t *testing.T) {
		data1, err := plugin.NewValidatedConfig(plugin.Unvalidated{Name: "foo", Version: "v1", Pattern: "*"})
		require.NoError(t, err)
		data2, err := plugin.NewValidatedConfig(plugin.Unvalidated{Name: "foo", Version: "v1", Pattern: "*"})
		require.NoError(t, err)
		assert.Equal(t, data1, data2)
	})
}
