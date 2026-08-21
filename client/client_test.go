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

package client

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/docker/secrets-engine/client/dockerhub"
	"github.com/docker/secrets-engine/x/api"
	healthv1 "github.com/docker/secrets-engine/x/api/health/v1"
	"github.com/docker/secrets-engine/x/api/health/v1/healthv1connect"
	pluginsv1 "github.com/docker/secrets-engine/x/api/plugins/v1"
	"github.com/docker/secrets-engine/x/api/plugins/v1/pluginsv1connect"
	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

var _ healthv1connect.VersionServiceHandler = &mockVersionService{}

type mockVersionService struct {
	version    string
	date       string
	commitHash string
}

func (m mockVersionService) GetVersion(_ context.Context, _ *connect.Request[healthv1.GetVersionRequest]) (*connect.Response[healthv1.GetVersionResponse], error) {
	return connect.NewResponse(healthv1.GetVersionResponse_builder{
		Version:    proto.String(m.version),
		Date:       proto.String(m.date),
		CommitHash: proto.String(m.commitHash),
	}.Build()), nil
}

func mockVersionEngine(t *testing.T, version, date, commitHash string) string {
	t.Helper()
	socketPath := testhelper.RandomShortSocketName()
	muxServer(t, socketPath, []handler{wrapHandler(healthv1connect.NewVersionServiceHandler(&mockVersionService{version: version, date: date, commitHash: commitHash}))})
	return socketPath
}

var _ pluginsv1connect.PluginManagementServiceHandler = &mockPluginsList{}

type mockPluginsList struct {
	list []PluginInfo
}

func (m mockPluginsList) ListPlugins(_ context.Context, _ *connect.Request[pluginsv1.ListPluginsRequest]) (*connect.Response[pluginsv1.ListPluginsResponse], error) {
	var plugins []*pluginsv1.Plugin
	for _, plugin := range m.list {
		var name string
		if plugin.Name != nil {
			name = plugin.Name.String()
		}
		var version string
		if plugin.Version != nil {
			version = plugin.Version.String()
		}
		b := pluginsv1.Plugin_builder{
			Name:          proto.String(name),
			Version:       proto.String(version),
			Disabled:      proto.Bool(plugin.Disabled),
			External:      proto.Bool(plugin.External),
			Configurable:  proto.Bool(plugin.Configurable),
			RunStatus:     plugin.RunStatus.Enum(),
			StatusMessage: proto.String(plugin.StatusMessage),
		}
		switch {
		case plugin.SecretsProvider != nil:
			b.SecretsProvider = pluginsv1.SecretsProvider_builder{
				Pattern: proto.String(plugin.SecretsProvider.Pattern.String()),
			}.Build()
		case plugin.AccessControlModule != nil:
			b.AccessControlModule = pluginsv1.AccessControlModule_builder{}.Build()
		}
		plugins = append(plugins, b.Build())
	}
	return connect.NewResponse(pluginsv1.ListPluginsResponse_builder{
		Plugins: plugins,
	}.Build()), nil
}

func (m mockPluginsList) EnablePlugin(_ context.Context, _ *connect.Request[pluginsv1.EnablePluginRequest]) (*connect.Response[pluginsv1.EnablePluginResponse], error) {
	return connect.NewResponse(pluginsv1.EnablePluginResponse_builder{}.Build()), nil
}

func (m mockPluginsList) DisablePlugin(_ context.Context, _ *connect.Request[pluginsv1.DisablePluginRequest]) (*connect.Response[pluginsv1.DisablePluginResponse], error) {
	return connect.NewResponse(pluginsv1.DisablePluginResponse_builder{}.Build()), nil
}

type handler struct {
	pattern string
	handler http.Handler
}

func muxServer(t *testing.T, socketPath string, handlers []handler) {
	t.Helper()
	_ = os.Remove(socketPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0o755))
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	mux := http.NewServeMux()
	for _, h := range handlers {
		mux.Handle(h.pattern, h.handler)
	}

	server := &http.Server{Handler: mux}

	go func() {
		_ = server.Serve(listener)
	}()

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		_ = server.Shutdown(shutdownCtx)
		_ = listener.Close()
		_ = os.RemoveAll(socketPath)
	})
}

func wrapHandler(pattern string, h http.Handler) handler {
	return handler{pattern: pattern, handler: h}
}

func mockListPluginsEngine(t *testing.T, plugins []PluginInfo) string {
	t.Helper()
	socketPath := testhelper.RandomShortSocketName()
	muxServer(t, socketPath, []handler{wrapHandler(pluginsv1connect.NewPluginManagementServiceHandler(&mockPluginsList{list: plugins}))})
	return socketPath
}

func Test_ListPlugins(t *testing.T) {
	t.Parallel()
	t.Run("external and internal configurable plugins", func(t *testing.T) {
		plugins := []PluginInfo{
			{
				Name:            api.MustNewName("foo"),
				Version:         api.MustNewVersion("v1"),
				SecretsProvider: &SecretsProviderMetadata{Pattern: secrets.MustParsePattern("**")},
				Configurable:    true,
				Disabled:        true,
			},
			{
				Name:            api.MustNewName("bar"),
				Version:         api.MustNewVersion("v1"),
				SecretsProvider: &SecretsProviderMetadata{Pattern: secrets.MustParsePattern("**")},
				External:        true,
				RunStatus:       pluginsv1.RunStatus_RUN_STATUS_CRASHED,
				StatusMessage:   "exit status 1: connection refused",
			},
			{
				Name:                api.MustNewName("baz"),
				Version:             api.MustNewVersion("v1"),
				AccessControlModule: &AccessControlModuleMetadata{},
				External:            true,
			},
		}
		socket := mockListPluginsEngine(t, plugins)
		client, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		m, err := PluginManagementFromClient(client)
		require.NoError(t, err)
		result, err := m.ListPlugins(t.Context())
		require.NoError(t, err)
		assert.Equal(t, plugins, result)
	})
	t.Run("no plugins", func(t *testing.T) {
		var plugins []PluginInfo
		socket := mockListPluginsEngine(t, plugins)
		client, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		m, err := PluginManagementFromClient(client)
		require.NoError(t, err)
		result, err := m.ListPlugins(t.Context())
		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("mix of valid and invalid plugin info", func(t *testing.T) {
		plugins := []PluginInfo{
			{
				Name: api.MustNewName("foo"),
			},
			{
				Name:            api.MustNewName("bar"),
				Version:         api.MustNewVersion("v1"),
				SecretsProvider: &SecretsProviderMetadata{Pattern: secrets.MustParsePattern("**")},
			},
		}
		socket := mockListPluginsEngine(t, plugins)
		client, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		m, err := PluginManagementFromClient(client)
		require.NoError(t, err)
		result, err := m.ListPlugins(t.Context())
		require.NoError(t, err)

		assert.Equal(t, []PluginInfo{
			{
				Name:            api.MustNewName("bar"),
				Version:         api.MustNewVersion("v1"),
				SecretsProvider: &SecretsProviderMetadata{Pattern: secrets.MustParsePattern("**")},
			},
		}, result)
	})
}

var _ resolverv1connect.AuthorizerServiceHandler = &mockAuthorizerService{}

type mockAuthorizerService struct {
	expiry   time.Time
	decision *resolverv1.Decision // nil leaves the decision unset
	err      error
	patterns []string
}

func (m *mockAuthorizerService) Authorize(_ context.Context, req *connect.Request[resolverv1.AuthorizeRequest]) (*connect.Response[resolverv1.AuthorizeResponse], error) {
	m.patterns = req.Msg.GetPatterns()
	if m.err != nil {
		return nil, m.err
	}
	return connect.NewResponse(resolverv1.AuthorizeResponse_builder{
		ExpiresAt: timestamppb.New(m.expiry),
		Decision:  m.decision,
	}.Build()), nil
}

func mockAuthorizeEngine(t *testing.T, m *mockAuthorizerService) string {
	t.Helper()
	socketPath := testhelper.RandomShortSocketName()
	muxServer(t, socketPath, []handler{wrapHandler(resolverv1connect.NewAuthorizerServiceHandler(m))})
	return socketPath
}

func Test_Authorize(t *testing.T) {
	t.Parallel()
	t.Run("forwards patterns and returns the decision", func(t *testing.T) {
		expiry := time.Now().Add(time.Hour).UTC()
		m := &mockAuthorizerService{expiry: expiry, decision: resolverv1.Decision_DECISION_ALLOW.Enum()}
		socket := mockAuthorizeEngine(t, m)
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)

		got, err := c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"), MustParsePattern("acme/api-token"))
		require.NoError(t, err)
		assert.True(t, got.Expiry.Equal(expiry), "expiry must round-trip")
		assert.True(t, got.Allow)
		assert.Equal(t, []string{"docker/auth/hub/joe", "acme/api-token"}, m.patterns)
	})
	t.Run("returns a deny decision without an error", func(t *testing.T) {
		m := &mockAuthorizerService{decision: resolverv1.Decision_DECISION_DENY.Enum()}
		socket := mockAuthorizeEngine(t, m)
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)

		got, err := c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"))
		require.NoError(t, err)
		assert.False(t, got.Allow)
	})
	t.Run("treats a missing decision as deny", func(t *testing.T) {
		m := &mockAuthorizerService{}
		socket := mockAuthorizeEngine(t, m)
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)

		got, err := c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"))
		require.NoError(t, err)
		assert.False(t, got.Allow, "a decision must be explicit to grant access")
	})
	t.Run("denied", func(t *testing.T) {
		m := &mockAuthorizerService{err: connect.NewError(connect.CodePermissionDenied, secrets.ErrAccessDenied)}
		socket := mockAuthorizeEngine(t, m)
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		_, err = c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"))
		require.ErrorIs(t, err, ErrAccessDenied)
	})
	t.Run("unavailable daemon", func(t *testing.T) {
		socketPath := testhelper.RandomShortSocketName()
		c, err := New(WithSocketPath(socketPath))
		require.NoError(t, err)
		_, err = c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"))
		require.ErrorIs(t, err, ErrSecretsEngineNotAvailable)
	})
}

func Test_Version(t *testing.T) {
	t.Parallel()
	t.Run("returns version info", func(t *testing.T) {
		socket := mockVersionEngine(t, "v1.2.3", "2026-03-26", "abc1234")
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		dv, err := c.Version(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "v1.2.3", dv.Version.String())
		assert.Equal(t, "2026-03-26", dv.Date)
		assert.Equal(t, "abc1234", dv.CommitHash)
	})
	t.Run("unavailable daemon", func(t *testing.T) {
		socketPath := testhelper.RandomShortSocketName()
		c, err := New(WithSocketPath(socketPath))
		require.NoError(t, err)
		_, err = c.Version(t.Context())
		require.ErrorIs(t, err, ErrSecretsEngineNotAvailable)
	})
}

func TestSecretsEngineUnavailable(t *testing.T) {
	socketPath := testhelper.RandomShortSocketName()
	client, err := New(WithSocketPath(socketPath))
	require.NoError(t, err)
	m, err := PluginManagementFromClient(client)
	require.NoError(t, err)
	_, err = m.ListPlugins(t.Context())
	require.ErrorIs(t, err, ErrSecretsEngineNotAvailable)
	_, err = client.GetSecrets(t.Context(), secrets.MustParsePattern("**"))
	require.ErrorIs(t, err, ErrSecretsEngineNotAvailable)
}

func TestHubAuth(t *testing.T) {
	client, err := New(WithSocketPath(testhelper.RandomShortSocketName()))
	require.NoError(t, err)
	assert.NotNil(t, client.HubAuth())
	assert.NotNil(t, client.HubAuth(dockerhub.Staging()))
}

func TestIsDialError(t *testing.T) {
	require.True(t, isDialError(&net.OpError{
		Op: "dial",
	}))
	require.True(t, isDialError(&net.OpError{
		Op: "connect",
	}))
	require.False(t, isDialError(nil))
}
