package plugin

import (
	"net/http"

	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/engine/internal/routes"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
)

func init() {
	routes.RegisterPrivatePluginRoute(registrationHandler)
}

func registrationHandler(c routes.PluginConfig) (routes.Path, http.Handler, error) {
	registrator := plugin.NewRegistrationLogic(c.ConfigValidator(), c.RegistrationChannel())
	path, h := resolverv1connect.NewEngineServiceHandler(&plugin.RegisterService{
		Logger:            c.Logger(),
		PluginRegistrator: registrator,
	})
	return routes.Path(path), h, nil
}
