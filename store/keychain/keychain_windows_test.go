//go:build windows

package keychain

import (
	"testing"

	"github.com/danieljoos/wincred"
	"github.com/stretchr/testify/assert"
)

func TestMapWindowsAttributes(t *testing.T) {
	t.Run("can map to windows attributes", func(t *testing.T) {
		attributes := map[string]string{
			"color": "green",
			"game":  "elden ring",
		}
		assert.EqualValues(t, []wincred.CredentialAttribute{
			{
				Keyword: "color",
				Value:   []byte("green"),
			},
			{
				Keyword: "game",
				Value:   []byte("elden ring"),
			},
		}, mapToWindowsAttributes(attributes))
	})
	t.Run("can map from windows attributes", func(t *testing.T) {
		wa := []wincred.CredentialAttribute{
			{
				Keyword: "color",
				Value:   []byte("green"),
			},
			{
				Keyword: "game",
				Value:   []byte("elden ring"),
			},
		}
		assert.EqualValues(t, map[string]string{
			"color": "green",
			"game":  "elden ring",
		}, mapFromWindowsAttributes(wa))
	})
	t.Run("nil attributes won't map anything", func(t *testing.T) {
		var attributes map[string]string
		assert.Empty(t, mapToWindowsAttributes(attributes))
	})
	t.Run("nil windows attributes won't map anything", func(t *testing.T) {
		var wa []wincred.CredentialAttribute
		assert.Empty(t, mapFromWindowsAttributes(wa))
	})
}
