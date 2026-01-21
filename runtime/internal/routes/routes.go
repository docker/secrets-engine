package routes

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/docker/secrets-engine/runtime/internal/config"
	"github.com/docker/secrets-engine/runtime/internal/plugin"
	"github.com/docker/secrets-engine/runtime/internal/registry"
)

type Config interface {
	config.Debugging
	config.Plugins
	Registry() registry.Registry
}

type PluginConfig interface {
	config.Debugging
	RegistrationChannel() chan plugin.RegistrationResult
	ConfigValidator() plugin.ConfigValidator
}

type (
	Path               string
	Route              func(Config) (Path, http.Handler, error)
	PublicRoute        Route
	PrivateRoute       Route
	PluginRoute        func(PluginConfig) (Path, http.Handler, error)
	PluginPublicRoute  PluginRoute
	PluginPrivateRoute PluginRoute
)

var errRouteDisabled = errors.New("disabled route")

var (
	pubRoutes  []PublicRoute
	privRoutes []PrivateRoute

	pubPluginRoutes  []PluginPublicRoute
	privPluginRoutes []PluginPrivateRoute
)

func registerPublicRoute(r PublicRoute) {
	pubRoutes = append(pubRoutes, r)
}

func registerPrivateRoute(r PrivateRoute) {
	privRoutes = append(privRoutes, r)
}

func RegisterPublicPluginRoute(r PluginPublicRoute) {
	pubPluginRoutes = append(pubPluginRoutes, r)
}

func RegisterPrivatePluginRoute(r PluginPrivateRoute) {
	privPluginRoutes = append(privPluginRoutes, r)
}

type routes struct {
	config.Engine
	registeredPublicRoutes []Path
	reg                    registry.Registry
	router                 *chi.Mux
}

var _ Config = &routes{}

func (r *routes) Registry() registry.Registry {
	return r.reg
}

type pluginRoutes struct {
	PluginConfig
	registeredPublicRoutes []Path
	router                 *chi.Mux
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

func registerPluginRoutes(r *pluginRoutes) error {
	for _, f := range pubPluginRoutes {
		path, h, err := f(r)
		if errors.Is(err, errRouteDisabled) {
			r.Logger().Printf("public plugin route disabled: %s", path)
			continue
		}
		if err != nil {
			return err
		}
		r.Logger().Printf("registering plugin public route: %s", path)
		r.registeredPublicRoutes = append(r.registeredPublicRoutes, path)

		// routes that end on the forward-slash '/' indicate that they handle sub-routes
		// themselves. In an http.ServeMux it would match any route with such a
		// prefix, but in go-chi/chi we need a wildcard '*'
		if strings.HasSuffix(string(path), "/") {
			path = path + "*"
		}
		r.router.Handle(string(path), h)
	}

	for _, f := range privPluginRoutes {
		path, h, err := f(r)
		if errors.Is(err, errRouteDisabled) {
			r.Logger().Printf("protected plugin route disabled: %s", path)
			continue
		}
		if err != nil {
			return err
		}
		r.Logger().Printf("registering protected plugin route: %s", path)
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

func SetupPlugins(cfg PluginConfig, router *chi.Mux) error {
	r := &pluginRoutes{
		PluginConfig: cfg,
		router:       router,
	}
	if err := registerPluginRoutes(r); err != nil {
		return err
	}
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
