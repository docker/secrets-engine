package routes

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/docker/secrets-engine/engine/internal/config"
	"github.com/docker/secrets-engine/engine/internal/registry"
)

type routeConfig interface {
	config.Debugging
	config.Plugins
	Registry() registry.Registry
}

type (
	routePath    string
	route        func(routeConfig) (routePath, http.Handler, error)
	publicRoute  route
	privateRoute route
)

var errRouteDisabled = errors.New("disabled route")

var (
	pubRoutes  []publicRoute
	privRoutes []privateRoute
)

func registerPublicRoute(r publicRoute) {
	pubRoutes = append(pubRoutes, r)
}

func registerPrivateRoute(r privateRoute) {
	privRoutes = append(privRoutes, r)
}

type routes struct {
	config.Engine
	registeredPublicRoutes []routePath
	reg                    registry.Registry
	router                 *chi.Mux
}

var _ routeConfig = &routes{}

func (r *routes) Registry() registry.Registry {
	return r.reg
}

func registerRoutes(r *routes) error {
	for _, f := range pubRoutes {
		path, h, err := f(r)
		if errors.Is(err, errRouteDisabled) {
			r.Logger().Printf("public route disabled: %s", path)
			continue
		}
		if err != nil {
			return err
		}
		r.Logger().Printf("registering public route: %s", path)
		r.registeredPublicRoutes = append(r.registeredPublicRoutes, path)

		// routes that end on the forward-slash '/' indicate that they handle sub-routes
		// themselves. In an http.ServeMux it would match any route with such a
		// prefix, but in go-chi/chi we need a wildcard '*'
		if strings.HasSuffix(string(path), "/") {
			path = path + "*"
		}
		r.router.Handle(string(path), h)
	}

	for _, f := range privRoutes {
		path, h, err := f(r)
		if errors.Is(err, errRouteDisabled) {
			r.Logger().Printf("protected route disabled: %s", path)
			continue
		}
		if err != nil {
			return err
		}
		r.Logger().Printf("registering protected route: %s", path)
		// routes that end on the forward-slash '/' indicate that they handle sub-routes
		// themselves. In an http.ServeMux it would match any route with such a
		// prefix, but in go-chi/chi we need a wildcard '*'
		if strings.HasSuffix(string(path), "/") {
			path = path + "*"
		}
		r.router.Handle(string(path), h)
	}

	return nil
}

func registerMiddleware(_ *routes) error {
	return nil
}

func Setup(cfg config.Engine, reg registry.Registry, router *chi.Mux) error {
	r := &routes{
		Engine: cfg,
		reg:    reg,
		router: router,
	}
	if err := registerMiddleware(r); err != nil {
		return err
	}
	if err := registerRoutes(r); err != nil {
		return err
	}
	return nil
}
