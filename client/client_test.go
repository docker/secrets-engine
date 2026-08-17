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
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/x/api"
	healthv1 "github.com/docker/secrets-engine/x/api/health/v1"
	"github.com/docker/secrets-engine/x/api/health/v1/healthv1connect"
	pluginsv1 "github.com/docker/secrets-engine/x/api/plugins/v1"
	"github.com/docker/secrets-engine/x/api/plugins/v1/pluginsv1connect"
	"github.com/docker/secrets-engine/x/api/resolver"
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

type pingClient struct {
	testhelper.MockResolver
	ping func(context.Context) (DaemonVersion, error)
}

func (p pingClient) Version(ctx context.Context) (DaemonVersion, error) {
	return p.ping(ctx)
}

func TestPreflight(t *testing.T) {
	t.Parallel()

	t.Run("passes when the engine responds", func(t *testing.T) {
		t.Parallel()
		c := pingClient{ping: func(_ context.Context) (DaemonVersion, error) {
			return DaemonVersion{}, nil
		}}
		require.NoError(t, preflight(t.Context(), c, time.Second))
	})

	t.Run("keeps the dial wrapping from Version", func(t *testing.T) {
		t.Parallel()
		engineErr := fmt.Errorf("%w: %w", ErrSecretsEngineNotAvailable, errors.New("connection refused"))
		c := pingClient{ping: func(_ context.Context) (DaemonVersion, error) {
			return DaemonVersion{}, engineErr
		}}
		err := preflight(t.Context(), c, time.Second)
		require.Error(t, err)
		assert.ErrorContains(t, err, "preflight ping")
		assert.ErrorIs(t, err, ErrSecretsEngineNotAvailable)
	})

	t.Run("wraps an explicit unavailable answer", func(t *testing.T) {
		t.Parallel()
		engineErr := connect.NewError(connect.CodeUnavailable, errors.New("draining"))
		c := pingClient{ping: func(_ context.Context) (DaemonVersion, error) {
			return DaemonVersion{}, engineErr
		}}
		err := preflight(t.Context(), c, time.Second)
		require.Error(t, err)
		assert.ErrorContains(t, err, "preflight ping")
		assert.ErrorIs(t, err, ErrSecretsEngineNotAvailable)
	})

	t.Run("keeps non-availability errors unwrapped", func(t *testing.T) {
		t.Parallel()
		engineErr := errors.New(`parsing daemon version "x": invalid`)
		c := pingClient{ping: func(_ context.Context) (DaemonVersion, error) {
			return DaemonVersion{}, engineErr
		}}
		err := preflight(t.Context(), c, time.Second)
		require.Error(t, err)
		assert.ErrorContains(t, err, "preflight ping")
		assert.ErrorIs(t, err, engineErr)
		assert.NotErrorIs(t, err, ErrSecretsEngineNotAvailable)
	})

	t.Run("gives up after the timeout when the engine hangs", func(t *testing.T) {
		t.Parallel()
		c := pingClient{ping: func(ctx context.Context) (DaemonVersion, error) {
			<-ctx.Done()
			return DaemonVersion{}, ctx.Err()
		}}
		// Watchdog parent: if preflight loses its own deadline, ping unblocks
		// here and the elapsed assertion fails fast, instead of the package
		// hanging until the go test panic. A parent deadline alone is not
		// enough — the regressed path would still surface DeadlineExceeded,
		// just later, and pass spuriously.
		watchdogCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		start := time.Now()
		err := preflight(watchdogCtx, c, 50*time.Millisecond)
		require.Error(t, err)
		require.Less(t, time.Since(start), 2*time.Second)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.ErrorIs(t, err, ErrSecretsEngineNotAvailable)
	})
}

// countingVersionService counts pings so tests can assert how often the
// preflight ran.
type countingVersionService struct {
	mockVersionService
	calls atomic.Int32
}

func (m *countingVersionService) GetVersion(ctx context.Context, req *connect.Request[healthv1.GetVersionRequest]) (*connect.Response[healthv1.GetVersionResponse], error) {
	m.calls.Add(1)
	return m.mockVersionService.GetVersion(ctx, req)
}

func resolverHandler(store map[secrets.ID]string) handler {
	return wrapHandler(resolverv1connect.NewResolverServiceHandler(resolver.NewResolverHandler(testhelper.MockResolver{Store: store})))
}

func TestGetSecretsPreflight(t *testing.T) {
	t.Parallel()

	store := map[secrets.ID]string{secrets.MustParseID("gh-token"): "ghp_abc123"}
	pattern := secrets.MustParsePattern("gh-token")

	t.Run("unbounded client pings before every resolution", func(t *testing.T) {
		t.Parallel()
		versions := &countingVersionService{mockVersionService: mockVersionService{version: "v1.2.3"}}
		socketPath := testhelper.RandomShortSocketName()
		muxServer(t, socketPath, []handler{
			wrapHandler(healthv1connect.NewVersionServiceHandler(versions)),
			resolverHandler(store),
		})
		c, err := New(WithSocketPath(socketPath))
		require.NoError(t, err)
		for range 2 {
			envs, err := c.GetSecrets(t.Context(), pattern)
			require.NoError(t, err)
			require.Len(t, envs, 1)
			assert.Equal(t, "ghp_abc123", string(envs[0].Value))
		}
		assert.Equal(t, int32(2), versions.calls.Load())
	})

	t.Run("bounded client skips the preflight", func(t *testing.T) {
		t.Parallel()
		socketPath := testhelper.RandomShortSocketName()
		// No version service mounted: a bounded client must resolve without
		// ever touching it.
		muxServer(t, socketPath, []handler{resolverHandler(store)})
		c, err := New(WithSocketPath(socketPath), WithTimeout(time.Second))
		require.NoError(t, err)
		envs, err := c.GetSecrets(t.Context(), pattern)
		require.NoError(t, err)
		require.Len(t, envs, 1)
	})

	t.Run("unbounded client requires the version service", func(t *testing.T) {
		t.Parallel()
		socketPath := testhelper.RandomShortSocketName()
		muxServer(t, socketPath, []handler{resolverHandler(store)})
		c, err := New(WithSocketPath(socketPath))
		require.NoError(t, err)
		_, err = c.GetSecrets(t.Context(), pattern)
		require.Error(t, err)
		assert.ErrorContains(t, err, "preflight ping")
		// The engine answered, so this is not misreported as unavailability.
		assert.NotErrorIs(t, err, ErrSecretsEngineNotAvailable)
	})

	t.Run("failed preflight is retried once the engine is up", func(t *testing.T) {
		t.Parallel()
		socketPath := testhelper.RandomShortSocketName()
		c, err := New(WithSocketPath(socketPath))
		require.NoError(t, err)
		_, err = c.GetSecrets(t.Context(), pattern)
		require.ErrorIs(t, err, ErrSecretsEngineNotAvailable)

		muxServer(t, socketPath, []handler{
			wrapHandler(healthv1connect.NewVersionServiceHandler(&mockVersionService{version: "v1.2.3"})),
			resolverHandler(store),
		})
		envs, err := c.GetSecrets(t.Context(), pattern)
		require.NoError(t, err)
		require.Len(t, envs, 1)
	})
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
