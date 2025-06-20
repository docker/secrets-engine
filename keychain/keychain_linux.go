//go:build secretservice

package keychain

import (
	"context"
	"errors"
	"fmt"

	"github.com/keybase/dbus"
	kc "github.com/keybase/go-keychain/secretservice"
)

const (
	// the default collection would be 'login'
	// gnome-keyring does not support creating collections
	keychainObjectPath = dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
)

// toSecretsService prefixes a secrets engine key
// The freedesktop.secrets API uses `/` to indicate <collection>/<id>
func toSecretsService(prefix string, id ID) string {
	// r := strings.NewReplacer("/", "__")
	return prefix + ":" + id.String()
}

// Erase implements Store.
//
//nolint:revive
func (k *keychainStore[T]) Erase(ctx context.Context, id ID) error {
	service, err := kc.NewService()
	if err != nil {
		return err
	}

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return err
	}
	defer service.CloseSession(session)

	attributes := map[string]string{
		"id":    id.String(),
		"owner": k.keyPrefix,
	}
	items, err := service.SearchCollection(keychainObjectPath, attributes)
	if err != nil {
		return err
	}

	if len(items) == 0 {
		return nil
	}

	return service.DeleteItem(items[0])
}

// Get implements Store.
//
//nolint:revive
func (k *keychainStore[T]) Get(ctx context.Context, id ID) (Secret, error) {
	service, err := kc.NewService()
	if err != nil {
		return nil, err
	}

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return nil, err
	}
	defer service.CloseSession(session)

	if err := service.Unlock([]dbus.ObjectPath{keychainObjectPath}); err != nil {
		return nil, err
	}

	attributes := map[string]string{
		"id":    id.String(),
		"owner": k.keyPrefix,
	}
	items, err := service.SearchCollection(keychainObjectPath, attributes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCredentialNotFound, err)
	}

	if len(items) == 0 {
		return nil, ErrCredentialNotFound
	}

	value, err := service.GetSecret(items[0], *session)
	if err != nil {
		return nil, err
	}

	secret := k.factory()
	if err := secret.Unmarshal(value); err != nil {
		return nil, err
	}

	return secret, nil
}

// GetAll implements Store.
//
//nolint:revive
func (k *keychainStore[T]) GetAll(ctx context.Context) (map[ID]Secret, error) {
	service, err := kc.NewService()
	if err != nil {
		return nil, err
	}

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return nil, err
	}
	defer service.CloseSession(session)

	if err := service.Unlock([]dbus.ObjectPath{keychainObjectPath}); err != nil {
		return nil, err
	}

	attributes := map[string]string{
		"owner": k.keyPrefix,
	}
	itemPaths, err := service.SearchCollection(keychainObjectPath, attributes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCredentialNotFound, err)
	}

	credentials := make(map[ID]Secret, len(itemPaths))
	for _, itemPath := range itemPaths {
		value, err := service.GetSecret(itemPath, *session)
		if err != nil {
			return nil, err
		}

		attributes, err := service.GetAttributes(itemPath)
		if err != nil {
			return nil, err
		}

		attrID, ok := attributes["id"]
		if !ok {
			return nil, errors.New("secret attributes does not contain `id` field")
		}

		secret := k.factory()
		if err := secret.Unmarshal(value); err != nil {
			return nil, err
		}
		secretID, err := ParseID(attrID)
		if err != nil {
			return nil, err
		}
		credentials[secretID] = secret
	}

	return credentials, nil
}

// Store implements Store.
//
//nolint:revive
func (k *keychainStore[T]) Store(ctx context.Context, id ID, secret Secret) error {
	service, err := kc.NewService()
	if err != nil {
		return err
	}

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return err
	}
	defer service.CloseSession(session)

	value, err := secret.Marshal()
	if err != nil {
		return err
	}

	sessSecret, err := session.NewSecret(value)
	if err != nil {
		return err
	}

	properties := kc.NewSecretProperties(toSecretsService(k.keyPrefix, id), map[string]string{
		"id":    id.String(),
		"owner": k.keyPrefix,
	})

	_, err = service.CreateItem(keychainObjectPath, properties, sessSecret, kc.ReplaceBehaviorReplace)
	if err != nil {
		return err
	}

	return nil
}
