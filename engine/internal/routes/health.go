package routes

import (
	"net/http"
)

func init() {
	registerPublicRoute(healthRoute)
}

func healthRoute(_ routeConfig) (routePath, http.Handler, error) {
	return "/health", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}), nil
}
