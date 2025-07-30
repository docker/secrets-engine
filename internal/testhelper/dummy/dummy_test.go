package dummy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/plugin"
)

func Test_dummyPluginBehaviour(t *testing.T) {
	t.Parallel()
	t.Run("no dashes in value", func(t *testing.T) {
		b := PluginBehaviour{Value: "in-valid"}
		_, err := b.ToString()
		assert.Error(t, err)
	})
	t.Run("with exit behaviour", func(t *testing.T) {
		b := PluginBehaviour{
			Value:          "foo",
			CrashBehaviour: &CrashBehaviour{OnNthSecretRequest: 1, ExitCode: 0},
		}
		s, err := b.ToString()
		require.NoError(t, err)
		r, err := ParsePluginBehaviour(s)
		require.NoError(t, err)
		assert.Equal(t, b, r)
	})
	t.Run("without exit behaviour", func(t *testing.T) {
		b := PluginBehaviour{Value: "foo"}
		s, err := b.ToString()
		require.NoError(t, err)
		r, err := ParsePluginBehaviour(s)
		require.NoError(t, err)
		assert.Equal(t, b, r)
	})
	t.Run("can marshal PluginCfg", func(t *testing.T) {
		now := time.Now().UTC()
		nowJSON, err := now.MarshalJSON()
		require.NoError(t, err)

		p := PluginCfg{
			Config: plugin.Config{
				Pattern: secrets.MustParsePattern("*"),
			},
			E: []secrets.Envelope{
				{
					ID:         secrets.MustNewID("com.test.test"),
					Value:      []byte("something"),
					CreatedAt:  now,
					ResolvedAt: now,
					ExpiresAt:  time.Time{},
				},
			},
			ErrGetSecret:   "",
			IgnoreSigint:   false,
			ErrConfigPanic: "",
			CrashBehaviour: &CrashBehaviour{},
		}
		result, err := json.Marshal(p)
		require.NoError(t, err)
		value := base64.StdEncoding.EncodeToString([]byte("something"))
		assert.JSONEq(t, fmt.Sprintf(
			`{
			"exitCode":0,
			"onNthSecretRequest":0,
			"version":"",
			"pattern":"*",
			"envelopes":[{"id":"com.test.test","value":"%s","createdAt":%[2]s,"resolvedAt":%[2]s,"expiresAt":"%s"}]}`,
			value, nowJSON, time.Time{}.UTC().Format(time.RFC3339)), string(result))
	})
	t.Run("can unmarshal PluginCfg", func(t *testing.T) {
		now := time.Now().UTC()
		nowJSON, err := now.MarshalJSON()
		require.NoError(t, err)

		value := base64.StdEncoding.EncodeToString([]byte("something"))
		data := fmt.Sprintf(
			`{
			"version":"",
			"pattern":"*",
			"envelopes":[{"id":"com.test.test","value":"%s","createdAt":%[2]s,"resolvedAt":%[2]s,"expiresAt":"%s"}],
			"exitCode":0,
			"onNthSecretRequest":0
			}`,
			value, nowJSON, time.Time{}.UTC().Format(time.RFC3339))
		var p PluginCfg
		require.NoError(t, json.Unmarshal([]byte(data), &p))
		expected := &PluginCfg{
			Config: plugin.Config{
				Pattern: secrets.MustParsePattern("*"),
				Version: "",
			},
			E: []secrets.Envelope{
				{
					ID:         secrets.MustNewID("com.test.test"),
					Value:      []byte("something"),
					CreatedAt:  now,
					ResolvedAt: now,
					ExpiresAt:  time.Time{}.UTC(),
				},
			},
			ErrGetSecret:   "",
			IgnoreSigint:   false,
			ErrConfigPanic: "",
			CrashBehaviour: &CrashBehaviour{
				ExitCode:           0,
				OnNthSecretRequest: 0,
			},
		}
		assert.Equal(t, expected, &p)
	})
}
