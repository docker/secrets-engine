package dockerauth

import (
	"context"
	"errors"
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

func (d dockerAuthPlugin) GetSecrets(ctx context.Context, request secrets.Request) ([]secrets.Envelope, error) {
	list, err := d.store.Filter(ctx, request.Pattern)
	if err != nil {
		return secrets.EnvelopeErrs(err), err
	}

	var errList []error
	var result []secrets.Envelope
	for id, value := range list {
		s, err := unpackValue(id, value)
		errList = append(errList, err)
		result = append(result, s)
	}

	return result, errors.Join(errList...)
}

func unpackValue(id store.ID, secret store.Secret) (secrets.Envelope, error) {
	val, err := secret.Marshal()
	if err != nil {
		return secrets.EnvelopeErr(err), err
	}
	m := secret.Metadata()

	// TODO: make this a schema so we know which keys exist
	var (
		createdAt time.Time
		expiresAt time.Time
	)

	if v, ok := m["createdAt"]; ok {
		createdAt, err = time.Parse(time.RFC3339, v)
		if err != nil {
			return secrets.EnvelopeErr(err), err
		}
	}
	if v, ok := m["expiresAt"]; ok {
		expiresAt, err = time.Parse(time.RFC3339, v)
		if err != nil {
			return secrets.EnvelopeErr(err), err
		}
	}

	return secrets.Envelope{
		ID:         id,
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
