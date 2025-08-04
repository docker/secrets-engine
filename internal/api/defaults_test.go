package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewPluginData(t *testing.T) {
	t.Parallel()
	t.Run("name is required", func(t *testing.T) {
		_, err := NewPluginData(PluginDataUnvalidated{Version: "foo", Pattern: "*"})
		assert.ErrorContains(t, err, "name is required")
	})
	t.Run("version is required", func(t *testing.T) {
		_, err := NewPluginData(PluginDataUnvalidated{Name: "foo", Pattern: "*"})
		assert.ErrorContains(t, err, "version is required")
	})
	t.Run("pattern must be valid", func(t *testing.T) {
		_, err := NewPluginData(PluginDataUnvalidated{Name: "foo", Version: "v1", Pattern: "*a*"})
		assert.ErrorContains(t, err, "invalid pattern")
	})
	t.Run("valid data can be compared to be equal", func(t *testing.T) {
		data1, err := NewPluginData(PluginDataUnvalidated{Name: "foo", Version: "v1", Pattern: "*"})
		require.NoError(t, err)
		data2, err := NewPluginData(PluginDataUnvalidated{Name: "foo", Version: "v1", Pattern: "*"})
		require.NoError(t, err)
		assert.Equal(t, data1, data2)
	})
}
