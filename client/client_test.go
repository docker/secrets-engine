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

	"github.com/docker/secrets-engine/x/api"
	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

var _ resolverv1connect.ListServiceHandler = &mockPluginsList{}

type mockPluginsList struct {
	list []PluginInfo
}

func (m mockPluginsList) ListPlugins(context.Context, *connect.Request[resolverv1.ListPluginsRequest]) (*connect.Response[resolverv1.ListPluginsResponse], error) {
	var plugins []*resolverv1.Plugin
	for _, plugin := range m.list {
		var name string
		if plugin.Name != nil {
			name = plugin.Name.String()
		}
		var version string
		if plugin.Version != nil {
			version = plugin.Version.String()
		}
		var pattern string
		if plugin.Pattern != nil {
			pattern = plugin.Pattern.String()
		}
		plugins = append(plugins, resolverv1.Plugin_builder{
			Name:     proto.String(name),
			Version:  proto.String(version),
			Pattern:  proto.String(pattern),
			External: proto.Bool(plugin.External),
		}.Build())
	}
	return connect.NewResponse(resolverv1.ListPluginsResponse_builder{
		Plugins: plugins,
	}.Build()), nil
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
	muxServer(t, socketPath, []handler{wrapHandler(resolverv1connect.NewListServiceHandler(&mockPluginsList{list: plugins}))})
	return socketPath
}

func Test_ListPlugins(t *testing.T) {
	t.Parallel()
	t.Run("external and internal plugins", func(t *testing.T) {
		plugins := []PluginInfo{
			{
				Name:    api.MustNewName("foo"),
				Version: api.MustNewVersion("v1"),
				Pattern: secrets.MustParsePattern("**"),
			},
			{
				Name:     api.MustNewName("bar"),
				Version:  api.MustNewVersion("v1"),
				Pattern:  secrets.MustParsePattern("**"),
				External: true,
			},
		}
		socket := mockListPluginsEngine(t, plugins)
		client, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		result, err := client.ListPlugins(t.Context())
		require.NoError(t, err)
		assert.Equal(t, plugins, result)
	})
	t.Run("no plugins", func(t *testing.T) {
		var plugins []PluginInfo
		socket := mockListPluginsEngine(t, plugins)
		client, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		result, err := client.ListPlugins(t.Context())
		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("mix of valid and invalid plugin info", func(t *testing.T) {
		plugins := []PluginInfo{
			{
				Name: api.MustNewName("foo"),
			},
			{
				Name:    api.MustNewName("bar"),
				Version: api.MustNewVersion("v1"),
				Pattern: secrets.MustParsePattern("**"),
			},
		}
		socket := mockListPluginsEngine(t, plugins)
		client, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		result, err := client.ListPlugins(t.Context())
		require.NoError(t, err)
		assert.Equal(t, []PluginInfo{
			{
				Name:    api.MustNewName("bar"),
				Version: api.MustNewVersion("v1"),
				Pattern: secrets.MustParsePattern("**"),
			},
		}, result)
	})
}

func TestSecretsEngineUnavailable(t *testing.T) {
	socketPath := testhelper.RandomShortSocketName()
	client, err := New(WithSocketPath(socketPath))
	require.NoError(t, err)
	_, err = client.ListPlugins(t.Context())
	require.ErrorIs(t, err, ErrSecretsEngineNotAvailable)
	_, err = client.GetSecrets(t.Context(), secrets.MustParsePattern("**"))
	require.ErrorIs(t, err, ErrSecretsEngineNotAvailable)
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
