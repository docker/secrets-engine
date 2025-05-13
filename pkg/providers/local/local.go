package local

import "github.com/docker/secrets-engine/pkg/secrets"

type Store struct{}

func New() *Store {
	return &Store{}
}

func (store *Store) GetSecret(req secrets.Request) (secrets.Envelope, error) {
	return getSecret(req.ID)
}

func (store *Store) PutSecret(id secrets.ID, value []byte) error {
	return putSecret(id, value)
}

func (store *Store) DeleteSecret(id secrets.ID) error {
	return deleteSecret(id)
}

func (store *Store) ListSecrets() ([]secrets.Envelope, error) {
	return listSecrets()
}
