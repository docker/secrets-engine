package routes

import (
	"net/http"

	service "github.com/docker/secrets-engine/engine/internal/services/resolver"
	"github.com/docker/secrets-engine/x/api/resolver"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
)

func init() {
	registerPrivateRoute(resolverHandler)
}

func resolverHandler(c routeConfig) (routePath, http.Handler, error) {
	r := service.NewService(c.Logger(), c.Tracker(), c.Registry())
	path, h := resolverv1connect.NewResolverServiceHandler(resolver.NewResolverHandler(r))
	return routePath(path), h, nil
}
