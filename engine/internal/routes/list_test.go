package routes

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/engine/internal/mocks"
	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/engine/internal/registry"
	"github.com/docker/secrets-engine/engine/internal/runtime/builtin"
	"github.com/docker/secrets-engine/x/api"
	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/testhelper"
)

func TestListService(t *testing.T) {
	reg := registry.NewManager(testhelper.TestLogger(t))
	listService := &ListService{registry: reg}
	result1, err := listService.ListPlugins(t.Context(), newListRequest())
	require.NoError(t, err)
	assert.Empty(t, result1.Msg.GetPlugins())
	p1 := &mocks.MockRuntime{RuntimeName: api.MustNewName("baz")}
	_, err = reg.Register(p1)
	require.NoError(t, err)
	p2 := &mocks.MockRuntime{RuntimeName: api.MustNewName("bar")}
	_, err = reg.Register(p2)
	require.NoError(t, err)
	mockConfig, err := plugin.NewValidatedConfig(plugin.Unvalidated{Name: "foo", Version: "v5", Pattern: "*"})
	require.NoError(t, err)
	p3, err := builtin.NewInternalRuntime(testhelper.TestLoggerCtx(t), &mocks.MockInternalPlugin{}, mockConfig, 100*time.Millisecond)
	require.NoError(t, err)
	_, err = reg.Register(p3)
	require.NoError(t, err)
	result2, err := listService.ListPlugins(t.Context(), newListRequest())
	require.NoError(t, err)
	assert.Equal(t, []pluginInfo{
		{name: "bar", version: "v7", pattern: "*", external: true},
		{name: "baz", version: "v7", pattern: "*", external: true},
		{name: "foo", version: "v5", pattern: "*", external: false},
	}, toPluginInfoList(result2.Msg.GetPlugins()))
}

type pluginInfo struct {
	name     string
	version  string
	pattern  string
	external bool
}

func toPluginInfoList(in []*resolverv1.Plugin) []pluginInfo {
	var result []pluginInfo
	for _, item := range in {
		result = append(result, pluginInfo{
			name:     item.GetName(),
			version:  item.GetVersion(),
			pattern:  item.GetPattern(),
			external: item.GetExternal(),
		})
	}
	return result
}

func newListRequest() *connect.Request[resolverv1.ListPluginsRequest] {
	return connect.NewRequest(resolverv1.ListPluginsRequest_builder{}.Build())
}
