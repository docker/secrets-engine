package credentialhelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/docker/docker-credential-helpers/client"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

type mockCredentialHelper struct {
	t *testing.T

	input     string
	operation string
	store     map[string]credentials.Credentials
}

func (m *mockCredentialHelper) Input(in io.Reader) {
	var buf []byte
	done := make(chan error, 1)

	go func() {
		data, err := io.ReadAll(in)
		buf = data
		done <- err
	}()

	select {
	case <-m.t.Context().Done():
		return
	case err := <-done:
		require.NoError(m.t, err)
		m.input = string(buf)
	}
}

func (m *mockCredentialHelper) Output() ([]byte, error) {
	switch m.operation {
	case "list":
		result := map[string]string{}
		for key, value := range m.store {
			result[key] = value.Username
		}
		out, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("mockCredentialHelper error: %s", err)
		}
		return out, nil
	case "store":
		var c credentials.Credentials
		err := json.Unmarshal([]byte(m.input), &c)
		if err != nil {
			return nil, fmt.Errorf("mockCredentialHelper error: %s", err)
		}
		m.store[c.ServerURL] = c
		return nil, nil
	case "erase":
		delete(m.store, m.input)
		return nil, nil
	case "get":
		credential, ok := m.store[m.input]
		if !ok {
			return nil, errors.New("not found")
		}
		out, err := json.Marshal(credential)
		if err != nil {
			return nil, fmt.Errorf("mockCredentialHelper error: %s", err)
		}
		return out, nil
	default:
		return nil, errors.New("unknown operation")
	}
}

var _ client.Program = &mockCredentialHelper{}

func TestCredentialHelper(t *testing.T) {
	t.Run("can get secret", func(t *testing.T) {
		store := map[string]credentials.Credentials{}

		c, err := New(testhelper.TestLogger(t),
			WithShellProgramFunc(func(args ...string) client.Program {
				return &mockCredentialHelper{
					t:         t,
					operation: args[0],
					store:     store,
				}
			}),
		)
		require.NoError(t, err)

		cred := credentials.Credentials{
			ServerURL: "https://test.com",
			Username:  "test",
			Secret:    "something",
		}
		store["https://test.com"] = cred
		result, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("**"))
		require.NoError(t, err)

		require.Len(t, result, 1)
		expected, err := json.Marshal(cred)
		require.NoError(t, err)

		require.Equal(t, secrets.Envelope{
			ID:         secrets.MustParseID("test.com"),
			Value:      expected,
			Provider:   "docker-credential-helper",
			Version:    "0.0.1",
			ResolvedAt: result[0].ResolvedAt,
		}, result[0])
	})

	t.Run("can prefix secret key", func(t *testing.T) {
		store := map[string]credentials.Credentials{}

		c, err := New(testhelper.TestLogger(t),
			WithKeyRewriter(func(serverURL string) (secrets.ID, error) {
				return secrets.ParseID("docker/test/" + strings.TrimPrefix(serverURL, "https://"))
			}),
			WithShellProgramFunc(func(args ...string) client.Program {
				return &mockCredentialHelper{
					t:         t,
					operation: args[0],
					store:     store,
				}
			}),
		)
		require.NoError(t, err)

		cred := credentials.Credentials{
			ServerURL: "https://test.com",
			Username:  "test",
			Secret:    "something",
		}
		store["https://test.com"] = cred
		result, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("docker/test/**"))
		require.NoError(t, err)

		require.Len(t, result, 1)
		expected, err := json.Marshal(cred)
		require.NoError(t, err)

		require.Equal(t, secrets.Envelope{
			ID:         secrets.MustParseID("docker/test/test.com"),
			Value:      expected,
			Provider:   "docker-credential-helper",
			Version:    "0.0.1",
			ResolvedAt: result[0].ResolvedAt,
		}, result[0])
	})

	t.Run("keys can have multiple path separators", func(t *testing.T) {
		store := map[string]credentials.Credentials{}

		c, err := New(testhelper.TestLogger(t),
			WithShellProgramFunc(func(args ...string) client.Program {
				return &mockCredentialHelper{
					t:         t,
					operation: args[0],
					store:     store,
				}
			}),
		)
		require.NoError(t, err)

		serverURL := "https://test.com/another/path"

		cred := credentials.Credentials{
			ServerURL: serverURL,
			Username:  "test",
			Secret:    "something",
		}
		store[serverURL] = cred
		result, err := c.GetSecrets(t.Context(), secrets.MustParsePattern("**"))
		require.NoError(t, err)

		require.Len(t, result, 1)
		expected, err := json.Marshal(cred)
		require.NoError(t, err)

		require.Equal(t, secrets.Envelope{
			ID:         secrets.MustParseID(strings.TrimPrefix(serverURL, "https://")),
			Value:      expected,
			Provider:   "docker-credential-helper",
			Version:    "0.0.1",
			ResolvedAt: result[0].ResolvedAt,
		}, result[0])
	})
}
