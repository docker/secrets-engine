// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"github.com/stretchr/testify/assert"
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

		require.Equal(t, secrets.Envelope{
			ID:    secrets.MustParseID("test.com"),
			Value: []byte(cred.Secret),
			Metadata: map[string]string{
				"ServerURL": cred.ServerURL,
				"Username":  cred.Username,
			},
			Provider:   "docker-credential-helper",
			Version:    "0.0.1",
			ResolvedAt: result[0].ResolvedAt,
		}, result[0])
	})

	t.Run("can prefix secret key", func(t *testing.T) {
		store := map[string]credentials.Credentials{}

		c, err := New(testhelper.TestLogger(t),
			WithKeyRewriter(func(serverURL, _ string) (secrets.ID, error) {
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

		require.Equal(t, secrets.Envelope{
			ID:    secrets.MustParseID("docker/test/test.com"),
			Value: []byte(cred.Secret),
			Metadata: map[string]string{
				"ServerURL": cred.ServerURL,
				"Username":  cred.Username,
			},
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

		require.Equal(t, secrets.Envelope{
			ID:    secrets.MustParseID(strings.TrimPrefix(serverURL, "https://")),
			Value: []byte(cred.Secret),
			Metadata: map[string]string{
				"ServerURL": cred.ServerURL,
				"Username":  cred.Username,
			},
			Provider:   "docker-credential-helper",
			Version:    "0.0.1",
			ResolvedAt: result[0].ResolvedAt,
		}, result[0])
	})
}

func TestDefaultKeyRewriter(t *testing.T) {
	for _, tc := range []struct {
		desc      string
		serverURL string
		expected  string
	}{
		{
			desc:      "valid URL with IP and without port",
			serverURL: "http://127.0.0.1/something",
			expected:  "127.0.0.1/something",
		},
		{
			desc:      "URL with IP and Port",
			serverURL: "http://192.162.233.123:8313/key/another",
			expected:  "192.162.233.123-port-8313/key/another",
		},
		{
			desc:      "URL with hostname",
			serverURL: "https://docker.com/credential/key",
			expected:  "docker.com/credential/key",
		},
		{
			desc:      "trailing forward-slash",
			serverURL: "https://example.com/credential/key/",
			expected:  "example.com/credential/key",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			assert.Equal(t, tc.expected, DefaultKeyRewriter(tc.serverURL))
		})
	}
}
