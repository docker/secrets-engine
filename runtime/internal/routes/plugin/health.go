package plugin

import (
	"net/http"

	"github.com/docker/secrets-engine/runtime/internal/routes"
)

func init() {
	routes.RegisterPublicPluginRoute(healthRoute)
}

func healthRoute(_ routes.PluginConfig) (routes.Path, http.Handler, error) {
	return "/health", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}), nil
}
