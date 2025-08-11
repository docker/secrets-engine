package mysecret

import (
	"context"

	"github.com/docker/secrets-engine/engine"
	"github.com/docker/secrets-engine/internal/secrets"
)

type mysecretPlugin struct{}

func (m mysecretPlugin) GetSecret(_ context.Context, request secrets.Request) (secrets.Envelope, error) {
	errNotFound := secrets.ErrNotFound
	return secrets.EnvelopeErr(request, errNotFound), errNotFound
}

func (m mysecretPlugin) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func NewMySecretPlugin() engine.Plugin {
	return &mysecretPlugin{}
}
