//go:build darwin

package keychain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertAttributes(t *testing.T) {
	t.Run("can convert attributes map into map of any", func(t *testing.T) {
		attributes := map[string]any{
			"game":  "elden ring",
			"color": "blue",
		}
		converted, err := convertAttributes(attributes)
		assert.NoError(t, err)
		assert.IsTypef(t, map[string]string{}, converted, "expected type after conversion to be map[string]string")
		assert.EqualValues(t, map[string]string{
			"game":  "elden ring",
			"color": "blue",
		}, converted)
	})
	t.Run("should error when a value has a non-string type", func(t *testing.T) {
		attributes := map[string]any{
			"score": 20,
			"color": "blue",
		}
		converted, err := convertAttributes(attributes)
		assert.ErrorContains(t, err, "unsupported type")
		assert.Nil(t, converted)
	})
	t.Run("nil attributes map should return empty map with no error", func(t *testing.T) {
		var attributes map[string]any
		converted, err := convertAttributes(attributes)
		assert.NoError(t, err)
		assert.Empty(t, converted)
	})
}
