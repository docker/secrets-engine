package service

import (
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
)

var _ store.Secret = &MyValue{}

type MyValue struct {
	Value []byte `json:"value"`
}

func (m *MyValue) Marshal() ([]byte, error) {
	return m.Value, nil
}

func (m *MyValue) Unmarshal(data []byte) error {
	m.Value = data
	return nil
}

func (m *MyValue) Metadata() map[string]string {
	return nil
}

func (m *MyValue) SetMetadata(map[string]string) error {
	return nil
}

func KCService() (store.Store, error) {
	kc, err := keychain.New(
		"io.docker.secrets",
		"docker-pass-cli",
		func() *MyValue {
			return &MyValue{}
		},
	)
	return kc, err
}
