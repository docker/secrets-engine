package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/docker/secrets-engine/pkg/handlers"
	"github.com/docker/secrets-engine/pkg/secrets"
)

type Engine struct {
	plugins []pluginRegistration
}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) GetSecret(ctx context.Context, req secrets.Request) (secrets.Envelope, error) {
	var errs []error

	if err := req.ID.Valid(); err != nil {
		return envelopeErr(req, err), err
	}

	for _, plugin := range e.plugins {
		if req.Provider != "" && req.Provider != plugin.name {
			continue
		}
		if !req.ID.Match(plugin.pattern) {
			continue
		}

		envelope, err := plugin.provider.GetSecret(ctx, req)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// we use the first matching, successful registration to resolve the secret.
		envelope.Provider = plugin.name

		if envelope.ResolvedAt.IsZero() {
			envelope.ResolvedAt = time.Now().UTC()
		}
		return envelope, nil
	}

	var err error
	if len(errs) == 0 {
		err = fmt.Errorf("secret %q: %w", req.ID, secrets.ErrNotFound)
	} else {
		err = errors.Join(errs...)
	}
	return envelopeErr(req, err), err
}

func envelopeErr(req secrets.Request, err error) secrets.Envelope {
	return secrets.Envelope{ID: req.ID, ResolvedAt: time.Now(), Error: err.Error()}
}

type pluginRegistration struct {
	name string
	//version  string
	pattern  string
	provider secrets.Resolver
}

func (e *Engine) Register(name, _, pattern string, provider secrets.Resolver) error {
	if slices.ContainsFunc(e.plugins, func(pr pluginRegistration) bool {
		return pr.name == name
	}) {
		return fmt.Errorf("provider name %q already registered", name)
	}

	e.plugins = append(e.plugins, pluginRegistration{
		name:     name,
		pattern:  pattern,
		provider: provider,
	})

	return nil
}

func (e *Engine) RegisterHandler() (string, http.Handler) {
	return "/secrets/register", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("not implemented")
	})
}

func (e *Engine) Handler() (string, http.Handler) {
	mux := http.NewServeMux()

	mux.Handle(handlers.Resolver(e))
	mux.Handle(e.RegisterHandler())
	mux.Handle("/secrets", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	}))

	return "/", mux
}
