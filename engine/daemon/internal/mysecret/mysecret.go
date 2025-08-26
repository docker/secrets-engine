package mysecret

import (
	"context"
	"errors"

	"github.com/docker/secrets-engine/engine"
	"github.com/docker/secrets-engine/mysecret/service"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

var _ engine.Plugin = &mysecretPlugin{}

var errUnknownSecretType = errors.New("unknown secret type")

type mysecretPlugin struct {
	kc     store.Store
	logger logging.Logger
}

func (m *mysecretPlugin) GetSecrets(ctx context.Context, request secrets.Request) ([]secrets.Envelope, error) {
	list, err := m.kc.Filter(ctx, request.Pattern)
	if err != nil {
		return nil, err
	}

	var result []secrets.Envelope
	for id, value := range list {
		s, err := unpackValue(id, value)
		if err != nil {
			m.logger.Errorf("unwrapping secret '%s': %s", id, err)
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
	impl, ok := secret.(*service.MyValue)
	if !ok {
		return nil, errUnknownSecretType
	}
	return &secrets.Envelope{
		ID:    id,
		Value: impl.Value,
	}, nil
}

func (m *mysecretPlugin) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func NewMySecretPlugin(logger logging.Logger) (engine.Plugin, error) {
	mysecretStore, err := service.KCService()
	if err != nil {
		return nil, err
	}
	return &mysecretPlugin{kc: mysecretStore, logger: logger}, nil
}
