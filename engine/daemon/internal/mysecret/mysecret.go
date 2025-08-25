package mysecret

import (
	"context"
	"errors"

	"github.com/docker/secrets-engine/engine"
	"github.com/docker/secrets-engine/mysecret/service"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/secrets"
)

var _ engine.Plugin = &mysecretPlugin{}

type mysecretPlugin struct {
	kc store.Store
}

func (m *mysecretPlugin) GetSecrets(ctx context.Context, request secrets.Request) ([]secrets.Envelope, error) {
	list, err := m.kc.Filter(ctx, request.Pattern)
	if err != nil {
		return nil, err
	}

	var errList []error
	var result []secrets.Envelope
	for id, value := range list {
		s, err := unpackValue(id, value)
		if err != nil {
			errList = append(errList, err)
			// TODO: log error
			continue
		}
		result = append(result, *s)
	}

	if len(result) == 0 && len(errList) > 0 {
		return nil, errors.Join(errList...)
	}

	return result, nil
}

func unpackValue(id store.ID, secret store.Secret) (*secrets.Envelope, error) {
	impl, ok := secret.(*service.MyValue)
	if !ok {
		return nil, errors.New("unknown secret type")
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

func NewMySecretPlugin() (engine.Plugin, error) {
	mysecretStore, err := service.KCService()
	if err != nil {
		return nil, err
	}
	return &mysecretPlugin{kc: mysecretStore}, nil
}
