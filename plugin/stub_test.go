package plugin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/internal/secrets"
)

func TestPluginConfigJSON(t *testing.T) {
	t.Run("can marshal Config", func(t *testing.T) {
		p := Config{
			Version: "1",
			Pattern: secrets.MustParsePattern("com.test.test"),
		}
		data, err := json.Marshal(p)
		require.NoError(t, err)
		assert.JSONEq(t, `{"version":"1","pattern":"com.test.test"}`, string(data))
	})
	t.Run("can unmarshal Config", func(t *testing.T) {
		var p Config
		require.NoError(t, json.Unmarshal([]byte(`{"version":"1","pattern":"com.test.test"}`), &p))
		assert.Equal(t, Config{
			Version: "1",
			Pattern: secrets.MustParsePattern("com.test.test"),
		}, p)
	})
}
