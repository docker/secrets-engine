package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/docker/secrets-engine/internal/secrets"
)

func Resolver(provider secrets.Resolver) (string, http.Handler) {
	return "/secrets/resolve", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprintf("parsing request: %v", err), http.StatusBadRequest)
			return
		}

		ids, ok := r.Form["id"]
		if !ok {
			http.Error(w, "at least one id parameter required", http.StatusBadRequest)
			return
		}

		// TODO: check token to get what the client actually has access to

		var candidates []secrets.Envelope
		for _, idUnsafe := range ids {
			id, err := secrets.ParseID(idUnsafe)
			if err != nil {
				candidates = append(candidates, secrets.Envelope{ID: secrets.ID(idUnsafe), Error: fmt.Sprintf("invalid identifier: %q", idUnsafe)})
				continue
			}
			envelope, err := provider.GetSecret(context.TODO(), secrets.Request{ID: id})
			if err != nil {
				candidates = append(candidates, secrets.Envelope{ID: secrets.ID(idUnsafe), Error: fmt.Sprintf("secret %s not available: %v", id, err)})
				continue
			}

			candidates = append(candidates, envelope)
		}

		var secretsResponse struct {
			Secrets []secrets.Envelope
		}
		secretsResponse.Secrets = candidates

		enc := json.NewEncoder(w)
		if err := enc.Encode(secretsResponse); err != nil {
			http.Error(w, fmt.Sprintf("encoding response failed: %v", err), http.StatusInternalServerError)
			return

		}
	})
}
