package store

import (
	"context"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
)

var _ store.Secret = &PassValue{}

type PassValue struct {
	Value []byte `json:"value"`
}

func (m *PassValue) Marshal() ([]byte, error) {
	return m.Value, nil
}

func (m *PassValue) Unmarshal(data []byte) error {
	m.Value = data
	return nil
}

func (m *PassValue) Metadata() map[string]string {
	return nil
}

func (m *PassValue) SetMetadata(map[string]string) error {
	return nil
}

func PassStore(serviceGroup string, opts ...keychain.Option) (store.Store, error) {
	kc, err := keychain.New(
		serviceGroup,
		"docker-pass-cli",
		func(_ context.Context, _ store.ID) *PassValue {
			return &PassValue{}
		},
		opts...,
	)
	return kc, err
}
