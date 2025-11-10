package pass

import (
	"context"
	"errors"

	"github.com/docker/secrets-engine/engine"
	pass "github.com/docker/secrets-engine/pass/store"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

var _ engine.Plugin = &passPlugin{}

var errUnknownSecretType = errors.New("unknown secret type")

type passPlugin struct {
	kc     store.Store
	logger logging.Logger
}

func (m *passPlugin) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	list, err := m.kc.Filter(ctx, pattern)
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
	impl, ok := secret.(*pass.PassValue)
	if !ok {
		return nil, errUnknownSecretType
	}
	return &secrets.Envelope{
		ID:    id,
		Value: impl.Value,
	}, nil
}

func (m *passPlugin) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func NewPassPlugin(logger logging.Logger, store store.Store) (engine.Plugin, error) {
	return &passPlugin{kc: store, logger: logger}, nil
}
