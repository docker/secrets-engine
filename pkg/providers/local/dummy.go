package local

import (
	"errors"
	"time"

	"github.com/docker/secrets-engine/pkg/secrets"
)

var errNotImplemented = errors.New("not implemented")

func getSecret(id secrets.ID) (secrets.Envelope, error) {
	return secrets.Envelope{
		ID:         id,
		ResolvedAt: time.Now().UTC(),
		Error:      errNotImplemented.Error(),
	}, errNotImplemented
}

func putSecret(secrets.ID, []byte) error {
	return errNotImplemented
}

func deleteSecret(secrets.ID) error {
	return errNotImplemented
}

func listSecrets() ([]secrets.Envelope, error) {
	return nil, errNotImplemented
}
