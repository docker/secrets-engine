package routes

import (
	"net/http"

	service "github.com/docker/secrets-engine/runtime/internal/services/resolver"
	"github.com/docker/secrets-engine/x/api/resolver"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
)

func init() {
	registerPrivateRoute(resolverHandler)
}

func resolverHandler(c Config) (Path, http.Handler, error) {
	r := service.NewService(c.Logger(), c.Tracker(), c.Registry())
	path, h := resolverv1connect.NewResolverServiceHandler(resolver.NewResolverHandler(r))
	return Path(path), h, nil
}
