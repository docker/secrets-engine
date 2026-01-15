package routes

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/engine/internal/registry"
	"github.com/docker/secrets-engine/engine/internal/runtime/builtin"
	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
)

func init() {
	registerPublicRoute(listHandler)
}

func listHandler(c Config) (Path, http.Handler, error) {
	l := &ListService{registry: c.Registry()}
	path, h := resolverv1connect.NewListServiceHandler(l)
	return Path(path), h, nil
}

var _ resolverv1connect.ListServiceHandler = &ListService{}

type ListService struct {
	registry registry.Registry
}

func (l ListService) ListPlugins(context.Context, *connect.Request[resolverv1.ListPluginsRequest]) (*connect.Response[resolverv1.ListPluginsResponse], error) {
	var plugins []*resolverv1.Plugin
	for plugin := range l.registry.Iterator() {
		plugins = append(plugins, resolverv1.Plugin_builder{
			Name:     proto.String(plugin.Name().String()),
			Version:  proto.String(plugin.Version().String()),
			Pattern:  proto.String(plugin.Pattern().String()),
			External: proto.Bool(!builtin.IsBuiltin(plugin)),
		}.Build())
	}
	return connect.NewResponse(resolverv1.ListPluginsResponse_builder{
		Plugins: plugins,
	}.Build()), nil
}
