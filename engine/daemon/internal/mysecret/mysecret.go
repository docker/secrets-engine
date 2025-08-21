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

func (m *mysecretPlugin) GetSecret(ctx context.Context, request secrets.Request) (secrets.Envelope, error) {
	s, err := m.kc.Get(ctx, request.ID)
	if errors.Is(err, store.ErrCredentialNotFound) {
		errNotFound := secrets.ErrNotFound
		return secrets.EnvelopeErr(request, errNotFound), errNotFound
	}
	if err != nil {
		return secrets.EnvelopeErr(request, err), err
	}
	impl, ok := s.(*service.MyValue)
	if !ok {
		err := errors.New("unknown secret type")
		return secrets.EnvelopeErr(request, err), err
	}
	return secrets.Envelope{
		ID:    request.ID,
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
