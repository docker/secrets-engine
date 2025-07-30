package secrets

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvelope(t *testing.T) {
	now := time.Now().UTC()
	nowJSON, err := now.MarshalJSON()
	require.NoError(t, err)

	t.Run("can encode envelope in JSON", func(t *testing.T) {
		envelope := &Envelope{
			ID:         MustNewID("com.test.test"),
			Value:      []byte("something"),
			Provider:   "test",
			Version:    "1",
			Error:      "",
			CreatedAt:  now,
			ResolvedAt: now,
			ExpiresAt:  time.Time{},
		}
		v, err := json.Marshal(envelope)
		require.NoError(t, err)
		assert.JSONEq(t,
			fmt.Sprintf(
				`{"id":"com.test.test","value":"%s","provider":"test","version":"1","createdAt":%[2]s,"resolvedAt":%[2]s, "expiresAt": "%s"}`,
				base64.StdEncoding.EncodeToString([]byte("something")), string(nowJSON), time.Time{}.UTC().Format(time.RFC3339)),
			string(v))
	})
	t.Run("can decode JSON to Envelope", func(t *testing.T) {
		var e Envelope
		now := time.Now().UTC()
		nowJSON, err := now.MarshalJSON()
		require.NoError(t, err)
		data := fmt.Sprintf(
			`{"id":"com.test.test","value":"%s","provider":"test","version":"1","createdAt":%[2]s,"resolvedAt":%[2]s, "expiresAt": "%s"}`,
			base64.StdEncoding.EncodeToString([]byte("something")), nowJSON, time.Time{}.UTC().Format(time.RFC3339))
		require.NoError(t, json.Unmarshal([]byte(data), &e))
		assert.Equal(t, &Envelope{
			ID:         MustNewID("com.test.test"),
			Value:      []byte("something"),
			Provider:   "test",
			Version:    "1",
			CreatedAt:  now,
			ResolvedAt: now,
			ExpiresAt:  time.Time{},
		}, &e)
	})

	envelopeValue := base64.StdEncoding.EncodeToString([]byte("something"))

	tests := []struct {
		desc string
		data json.RawMessage
		err  string
	}{
		{
			desc: "will error on invalid id",
			data: json.RawMessage(`{"id":"i-am-invalid$!#"}`),
			err:  "secrets.Envelope could not decode secrets.ID",
		},
		{
			desc: "will error on missing value",
			data: json.RawMessage(`{"id":"com.test.test"}`),
			err:  "secrets.Envelope: `value` must be set",
		},
		{
			desc: "will error on createdAt missing",
			data: json.RawMessage(`{"id":"com.test.test","value":"` + string(envelopeValue) + `"}`),
			err:  "secrets.Envelope: `createdAt` must be set",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			var e Envelope
			require.ErrorContains(t, json.Unmarshal(tc.data, &e), tc.err)
		})
	}
}
