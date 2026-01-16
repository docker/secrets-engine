package pass

import (
	"context"
	"errors"

	"github.com/docker/secrets-engine/plugin"
	pass "github.com/docker/secrets-engine/plugins/pass/store"
	"github.com/docker/secrets-engine/store"
)

var _ plugin.Plugin = &passPlugin{}

var errUnknownSecretType = errors.New("unknown secret type")

type passPlugin struct {
	kc     store.Store
	logger plugin.Logger
}

func (m *passPlugin) GetSecrets(ctx context.Context, pattern plugin.Pattern) ([]plugin.Envelope, error) {
	list, err := m.kc.Filter(ctx, pattern)
	if err != nil {
		return nil, err
	}

	var result []plugin.Envelope
	for id, value := range list {
		s, err := unpackValue(id, value)
		if err != nil {
			m.logger.Errorf("unwrapping secret '%s': %s", id, err)
			continue
		}
		result = append(result, *s)
	}

	if len(result) == 0 {
		return nil, plugin.ErrNotFound
	}

	return result, nil
}

func unpackValue(id store.ID, secret store.Secret) (*plugin.Envelope, error) {
	impl, ok := secret.(*pass.PassValue)
	if !ok {
		return nil, errUnknownSecretType
	}
	return &plugin.Envelope{
		ID:    id,
		Value: impl.Value,
	}, nil
}

func (m *passPlugin) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func NewPassPlugin(logger plugin.Logger, store store.Store) (plugin.Plugin, error) {
	return &passPlugin{kc: store, logger: logger}, nil
}
