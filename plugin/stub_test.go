// Copyright 2026 Docker, Inc.
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

package plugin

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client/version"
	"github.com/docker/secrets-engine/secrets"
)

func Test_newStub(t *testing.T) {
	t.Run("without logger", func(t *testing.T) {
		socket := rand.Text() + ".sock"
		l, err := net.Listen("unix", socket)
		require.NoError(t, err)
		t.Cleanup(func() { l.Close() })
		go runUncheckedDummyAcceptor(&testLogger{t}, l)
		conn, err := net.Dial("unix", socket)
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })

		s, err := NewSecretsProvider(&mockPlugin{}, Config{
			Version:               version.MustNewVersion("v1"),
			SecretsProviderConfig: &SecretsProviderConfig{Pattern: secrets.MustParsePattern("*")},
		}, WithPluginName("test-plugin"), WithConnection(conn))
		require.NoError(t, err)
		assert.NotNil(t, s)
	})
}
