package routes

import "net/http"

func init() {
	registerPrivateRoute(authSecretsHandler)
}

func authSecretsHandler(c Config) (Path, http.Handler, error) {
}
