// The keychain package for Linux uses the org.freedesktop.secret service API
// over dbus.
// For more information on the Secret Service API, see https://specifications.freedesktop.org/secret-service-spec/latest/index.html.
package keychain

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/docker/secrets-engine/store"
	"github.com/keybase/dbus"
	kc "github.com/keybase/go-keychain/secretservice"
)

const (
	// the default collection in most X11 sessions would be 'login'
	// it is created by default through PAM, see https://wiki.gnome.org/Projects/GnomeKeyring/Pam.
	//
	// NOTE: do not use this directly, always call [getDefaultCollection]
	loginKeychainObjectPath = dbus.ObjectPath("/org/freedesktop/secrets/collection/login")

	// used to list all available collections on the secret service API
	//
	// https://specifications.freedesktop.org/secret-service-spec/latest/org.freedesktop.Secret.Service.html
	secretServiceCollectionProperty = "org.freedesktop.Secret.Service.Collections"

	// used to get the dbus object path of an aliased collection
	// An common alias would be 'default'
	// https://specifications.freedesktop.org/secret-service-spec/latest/org.freedesktop.Secret.Service.html
	secretServiceGetAliasObjectPath = "org.freedesktop.Secret.Service.ReadAlias"

	// used to check if the collection is locked
	//
	// https://specifications.freedesktop.org/secret-service-spec/latest/org.freedesktop.Secret.Collection.html
	secretServiceIsCollectionLockedProperty = "org.freedesktop.Secret.Collection.Locked"
)

// newItemAttributes configures the default attributes for each item in the keychain
//
// It sets the `service:group` and `service:name` attributes as well as the
// secret id.
//
// id can also be empty and is used in cases were we only want to filter on the
// service:group and service:name attributes.
func newItemAttributes[T store.Secret](id string, k *keychainStore[T]) map[string]string {
	attributes := map[string]string{
		"service:group": k.serviceGroup,
		"service:name":  k.serviceName,
	}
	if id != "" {
		attributes["id"] = id
	}
	return attributes
}

// getDefaultCollection gets the secret service collection dbus object path.
//
// It prefers the loginKeychainObjectPath, since most users on X11 would have
// this available via PAM, see https://wiki.gnome.org/Projects/GnomeKeyring/Pam.
//
// As a fallback it queries the secret service for the default collection.
// It is possible that the host does not have a collection set up, in that case
// the only option is to error.
func getDefaultCollection(service *kc.SecretService) (dbus.ObjectPath, error) {
	variant, err := service.ServiceObj().GetProperty(secretServiceCollectionProperty)
	if err != nil {
		return "", err
	}
	collections, ok := variant.Value().([]dbus.ObjectPath)
	if !ok {
		return "", errors.New("could not list keychain collections")
	}
	// choose the 'login' collection if it exists
	if slices.Contains(collections, loginKeychainObjectPath) {
		return loginKeychainObjectPath, nil
	}
	// we need to fallback to the default collection
	var defaultKeychainObjectPath dbus.ObjectPath
	err = service.ServiceObj().
		Call(secretServiceGetAliasObjectPath, 0, "default").
		Store(&defaultKeychainObjectPath)
	if err != nil {
		return "", err
	}

	if !defaultKeychainObjectPath.IsValid() {
		return "", errors.New("the default collection object path is invalid")
	}

	return defaultKeychainObjectPath, nil
}

var errCollectionLocked = errors.New("collection is locked")

// isCollectionUnlocked verifies if the collection is unlocked.
//
// It returns the errCollectionLocked error by default if the collection is locked.
// On any other error, it returns the underlying error instead.
func isCollectionUnlocked(service *kc.SecretService) error {
	variant, err := service.ServiceObj().GetProperty(secretServiceIsCollectionLockedProperty)
	if err != nil {
		return err
	}
	if locked, ok := variant.Value().(bool); ok && !locked {
		return nil
	}
	return errCollectionLocked
}

func (k *keychainStore[T]) Delete(ctx context.Context, id store.ID) error {
	if err := id.Valid(); err != nil {
		return err
	}

	service, err := kc.NewService()
	if err != nil {
		return err
	}

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return err
	}
	defer service.CloseSession(session)

	objectPath, err := getDefaultCollection(service)
	if err != nil {
		return err
	}

	err = isCollectionUnlocked(service)
	if err != nil && !errors.Is(err, errCollectionLocked) {
		return err
	}
	if errors.Is(err, errCollectionLocked) {
		if err := service.Unlock([]dbus.ObjectPath{objectPath}); err != nil {
			return err
		}
	}

	attributes := newItemAttributes(id.String(), k)
	items, err := service.SearchCollection(objectPath, attributes)
	if err != nil {
		return err
	}

	if len(items) == 0 {
		return nil
	}

	return service.DeleteItem(items[0])
}

func (k *keychainStore[T]) Get(ctx context.Context, id store.ID) (store.Secret, error) {
	if err := id.Valid(); err != nil {
		return nil, err
	}

	service, err := kc.NewService()
	if err != nil {
		return nil, err
	}

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return nil, err
	}
	defer service.CloseSession(session)

	objectPath, err := getDefaultCollection(service)
	if err != nil {
		return nil, err
	}

	err = isCollectionUnlocked(service)
	if err != nil && !errors.Is(err, errCollectionLocked) {
		return nil, err
	}
	if errors.Is(err, errCollectionLocked) {
		if err := service.Unlock([]dbus.ObjectPath{objectPath}); err != nil {
			return nil, err
		}
	}

	attributes := newItemAttributes(id.String(), k)
	items, err := service.SearchCollection(objectPath, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search collection: %w", err)
	}

	if len(items) == 0 {
		return nil, store.ErrCredentialNotFound
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

func (k *keychainStore[T]) GetAll(ctx context.Context) (map[store.ID]store.Secret, error) {
	service, err := kc.NewService()
	if err != nil {
		return nil, err
	}

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return nil, err
	}
	defer service.CloseSession(session)

	objectPath, err := getDefaultCollection(service)
	if err != nil {
		return nil, err
	}

	err = isCollectionUnlocked(service)
	if err != nil && !errors.Is(err, errCollectionLocked) {
		return nil, err
	}
	if errors.Is(err, errCollectionLocked) {
		if err := service.Unlock([]dbus.ObjectPath{objectPath}); err != nil {
			return nil, err
		}
	}

	attributes := newItemAttributes("", k)
	itemPaths, err := service.SearchCollection(objectPath, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search collection: %w", err)
	}

	if len(itemPaths) == 0 {
		return nil, store.ErrCredentialNotFound
	}

	credentials := make(map[store.ID]store.Secret, len(itemPaths))
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
		secretID, err := store.ParseID(attrID)
		if err != nil {
			return nil, err
		}
		credentials[secretID] = secret
	}

	return credentials, nil
}

func (k *keychainStore[T]) Save(ctx context.Context, id store.ID, secret store.Secret) error {
	if err := id.Valid(); err != nil {
		return err
	}

	service, err := kc.NewService()
	if err != nil {
		return err
	}

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return err
	}
	defer service.CloseSession(session)

	objectPath, err := getDefaultCollection(service)
	if err != nil {
		return err
	}

	err = isCollectionUnlocked(service)
	if err != nil && !errors.Is(err, errCollectionLocked) {
		return err
	}
	if errors.Is(err, errCollectionLocked) {
		if err := service.Unlock([]dbus.ObjectPath{objectPath}); err != nil {
			return err
		}
	}

	value, err := secret.Marshal()
	if err != nil {
		return err
	}

	sessSecret, err := session.NewSecret(value)
	if err != nil {
		return err
	}

	attributes := newItemAttributes(id.String(), k)
	label := k.itemLabel(id)
	properties := kc.NewSecretProperties(label, attributes)

	_, err = service.CreateItem(objectPath, properties, sessSecret, kc.ReplaceBehaviorReplace)
	if err != nil {
		return err
	}

	return nil
}
