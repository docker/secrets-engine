package dockerauth

import (
	"context"
	"time"

	"github.com/docker/docker-auth/auth/authstore"

	"github.com/docker/secrets-engine/engine"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

const (
	serviceGroup = "io.Docker.Auth"
	serviceName  = "docker-auth-cli"
)

type dockerAuthPlugin struct {
	store  store.Store
	logger logging.Logger
}

func (d dockerAuthPlugin) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	list, err := d.store.Filter(ctx, pattern)
	if err != nil {
		return nil, err
	}

	var result []secrets.Envelope
	for id, value := range list {
		s, err := unpackValue(id, value)
		if err != nil {
			d.logger.Errorf("unwrapping secret '%s': %s", id, err)
			continue
		}
		result = append(result, *s)
	}

	if len(result) == 0 {
		return nil, secrets.ErrNotFound
	}

	return result, nil
}

func unpackValue(id store.ID, secret store.Secret) (*secrets.Envelope, error) {
	val, err := secret.Marshal()
	if err != nil {
		return nil, err
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
			return nil, err
		}
	}
	if v, ok := m["expiresAt"]; ok {
		expiresAt, err = time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, err
		}
	}

	return &secrets.Envelope{
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

func NewDockerAuthPlugin(logger logging.Logger) (engine.Plugin, error) {
	s, err := authstore.NewStore(serviceGroup, serviceName)
	if err != nil {
		return nil, err
	}
	return &dockerAuthPlugin{
		store:  s,
		logger: logger,
	}, nil
}
