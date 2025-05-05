package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Envelope struct {
	ID         ID
	Value      []byte    `json:",omitzero"`
	Provider   string    `json:",omitzero"`
	Version    string    `json:",omitzero"`
	Error      string    `json:",omitzero"`
	CreatedAt  time.Time `json:",omitzero"`
	ResolvedAt time.Time `json:",omitzero"`
	ExpiresAt  time.Time `json",omitzero"`
}

func Handler(provider SecretProvider) (string, http.Handler) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /secrets/resolve", func(w http.ResponseWriter, r *http.Request) {
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

		var secrets []Envelope
		for _, idUnsafe := range ids {
			id, err := ParseID(idUnsafe)
			if err != nil {
				secrets = append(secrets, Envelope{ID: ID(idUnsafe), Error: fmt.Sprintf("invalid identifier: %q", idUnsafe)})
				continue
			}
			envelope, err := provider.GetSecret(id)
			if err != nil {
				secrets = append(secrets, Envelope{ID: ID(idUnsafe), Error: fmt.Sprintf("secret %s not available: %v", id, err)})
				continue
			}

			secrets = append(secrets, envelope)
		}

		var secretsResponse struct {
			Secrets []Envelope
		}
		secretsResponse.Secrets = secrets

		enc := json.NewEncoder(w)
		if err := enc.Encode(secretsResponse); err != nil {
			http.Error(w, fmt.Sprintf("encoding response failed: %v", err), http.StatusInternalServerError)
			return

		}
	})
	return "/secrets", mux
}
