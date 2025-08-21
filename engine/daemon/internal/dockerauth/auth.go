package dockerauth

import (
	"context"
	"time"

	"github.com/docker/docker-auth/auth/authstore"

	"github.com/docker/secrets-engine/engine"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/secrets"
)

const (
	serviceGroup = "io.Docker.Auth"
	serviceName  = "docker-auth-cli"
)

type dockerAuthPlugin struct {
	store store.Store
}

func (d dockerAuthPlugin) GetSecret(ctx context.Context, request secrets.Request) (secrets.Envelope, error) {
	secret, err := d.store.Get(ctx, request.ID)
	if err != nil {
		return secrets.EnvelopeErr(request, err), err
	}
	val, err := secret.Marshal()
	if err != nil {
		return secrets.EnvelopeErr(request, err), err
	}

	// TODO: make this a schema so we know which keys exist
	m := secret.Metadata()

	var (
		createdAt time.Time
		expiresAt time.Time
	)

	if v, ok := m["createdAt"]; ok {
		createdAt, err = time.Parse(time.RFC3339, v)
		if err != nil {
			return secrets.EnvelopeErr(request, err), err
		}
	}
	if v, ok := m["expiresAt"]; ok {
		expiresAt, err = time.Parse(time.RFC3339, v)
		if err != nil {
			return secrets.EnvelopeErr(request, err), err
		}
	}

	return secrets.Envelope{
		ID:         request.ID,
		Value:      val,
		Provider:   serviceName,
		Version:    "0.0.1",
		CreatedAt:  createdAt,
		ResolvedAt: time.Now(),
		ExpiresAt:  expiresAt,
	}, nil
}

func (d dockerAuthPlugin) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func NewDockerAuthPlugin() (engine.Plugin, error) {
	s, err := authstore.NewStore(serviceGroup, serviceName)
	if err != nil {
		return nil, err
	}
	return &dockerAuthPlugin{
		store: s,
	}, nil
}
