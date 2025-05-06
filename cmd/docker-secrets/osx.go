//go:build darwin && cgo
// +build darwin,cgo

package main

import (
	"fmt"
	"time"

	"github.com/docker/secrets-engine/pkg/secrets"
	"github.com/keybase/go-keychain"
)

const (
	KeychainItemAttrService     = "DockerSecretsEngine"
	KeychainItemAttrAccessGroup = "test.com.docker.secrets"
)

// from https://github.com/docker/docker-credential-helpers/blob/f9d3010165b642df37215b1be945552f2c6f0e3b/osxkeychain/osxkeychain.go#L24
const (
	// errCredentialsNotFound is the specific error message returned by OS X
	// when the credentials are not in the keychain.
	errCredentialsNotFound = "The specified item could not be found in the keychain. (-25300)"
	// errInteractionNotAllowed is the specific error message returned by OS X
	// when environment does not allow showing dialog to unlock keychain.
	errInteractionNotAllowed = "User interaction is not allowed. (-25308)"
)

func getSecret(id secrets.ID) (secrets.Envelope, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(KeychainItemAttrService)
	query.SetAccount("containersecret:" + string(id))
	query.SetLabel(string(id))
	query.SetAccessGroup(KeychainItemAttrAccessGroup)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)
	query.SetReturnAttributes(true)
	results, err := keychain.QueryItem(query)
	if err != nil || len(results) != 1 {
		if err == nil {
			if len(results) > 1 {
				err = fmt.Errorf("received %v secret results for %q", len(results), id)
			}
			if len(results) < 1 {
				err = fmt.Errorf("secret %q: %w", id, secrets.ErrNotFound)
			}
		}
		return secrets.Envelope{ID: id, ResolvedAt: time.Now().UTC(), Error: err.Error()}, mapNotFound(err)
	}

	return secrets.Envelope{
		ID:         id,
		Value:      results[0].Data,
		CreatedAt:  results[0].CreationDate,
		ResolvedAt: time.Now().UTC(),
		Provider:   "local",
	}, nil
}

func putSecret(id secrets.ID, value []byte) error {
	_ = deleteSecret(id) // always delete first, ignore error

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(KeychainItemAttrService)
	item.SetAccount("containersecret:" + string(id))
	item.SetLabel(string(id))
	item.SetData(value)
	item.SetAccessGroup(KeychainItemAttrAccessGroup)
	item.SetAccessible(keychain.AccessibleAlways)
	keychain.AddItem(item)
	return nil
}

func deleteSecret(id secrets.ID) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(KeychainItemAttrService)
	item.SetAccount("containersecret" + ":" + string(id))
	item.SetLabel(string(id))
	err := keychain.DeleteItem(item)
	return mapNotFound(err)
}

func listSecrets() ([]secrets.Envelope, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(KeychainItemAttrService)
	query.SetMatchLimit(keychain.MatchLimitAll)
	query.SetReturnAttributes(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, fmt.Errorf("querying secrets: %w", err)
	}

	envelopes := make([]secrets.Envelope, 0, len(results))
	for _, result := range results {
		if result.Label == "" {
			continue
		}
		id := secrets.ID(result.Label)
		envelope := secrets.Envelope{
			ID:         id,
			CreatedAt:  result.CreationDate,
			ResolvedAt: time.Now().UTC(),
			Provider:   "local",
		}

		envelopes = append(envelopes, envelope)
	}

	return envelopes, nil
}

func mapNotFound(err error) error {
	if err == nil {
		return nil
	}
	if err.Error() == errCredentialsNotFound {
		return secrets.ErrNotFound
	}
	return err
}
