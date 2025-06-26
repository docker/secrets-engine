package keychain

import (
	"context"
	"errors"

	"github.com/docker/secrets-engine/store"
	kc "github.com/keybase/go-keychain"
)

var (
	ErrInteractionNotAllowed = errors.New("cannot prompt the user for password")
	ErrAuthFailed            = errors.New("user incorrectly enterered their credentials")
)

// newKeychainItem creates a new keychain item with valid default parameters.
//
// It uses a generic password class, which is suitable for most use cases.
//
// By default, the item will only return one secret when queried.
//
// The id parameter can be empty, in which case the item will search based on
// the service name and group, but not the item label or account.
func newKeychainItem[T store.Secret](id string, k *keychainStore[T]) kc.Item {
	item := kc.NewItem()
	// generic password is used here as we don't know what we are storing
	// the main difference between a generic and internet password is the
	// addition of a server URL
	item.SetSecClass(kc.SecClassGenericPassword)
	// MatchLimitOne is used to ensure we only get one item back when querying
	// set this to MatchLimitAll if you want to retrieve all items
	item.SetMatchLimit(kc.MatchLimitOne)
	item.SetAccessible(kc.AccessibleAfterFirstUnlock)
	item.SetReturnAttributes(true)

	item.SetService(k.serviceName)
	item.SetAccessGroup(k.serviceGroup)

	if id != "" {
		item.SetAccount(id)
	}

	return item
}

// getItemWithData retrieves a keychain item with its data.
//
// It uses the SetReturnData attribute to query for an item with its data.
// It cannot be used with MatchLimitAll, as it will return an error.
// https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)#Discussion
func getItemWithData[T store.Secret](id string, k *keychainStore[T]) (*kc.QueryResult, error) {
	item := newKeychainItem(id, k)
	item.SetReturnData(true)

	results, err := kc.QueryItem(item)
	if err != nil {
		return nil, mapKeychainError(err)
	}
	if len(results) == 0 {
		return nil, store.ErrCredentialNotFound
	}

	return &results[0], nil
}

func (k *keychainStore[T]) Delete(ctx context.Context, id store.ID) error {
	if err := id.Valid(); err != nil {
		return err
	}

	item := newKeychainItem(id.String(), k)
	return mapKeychainError(kc.DeleteItem(item))
}

func (k *keychainStore[T]) Get(ctx context.Context, id store.ID) (store.Secret, error) {
	if err := id.Valid(); err != nil {
		return nil, err
	}

	result, err := getItemWithData(id.String(), k)
	if err != nil {
		return nil, err
	}

	secret := k.factory()
	if err := secret.Unmarshal(result.Data); err != nil {
		return nil, err
	}
	return secret, nil
}

func (k *keychainStore[T]) GetAll(ctx context.Context) (map[store.ID]store.Secret, error) {
	item := newKeychainItem("", k)

	// We use the MatchLimitAll attribute to query for multiple items from the
	// store. It cannot be used with item.SetReturnData.
	// https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)#Discussion
	item.SetMatchLimit(kc.MatchLimitAll)

	results, err := kc.QueryItem(item)
	if err != nil {
		return nil, mapKeychainError(err)
	}

	creds := make(map[store.ID]store.Secret, len(results))
	for _, result := range results {
		id, err := store.ParseID(result.Account)
		if err != nil {
			return nil, err
		}

		i, err := getItemWithData(id.String(), k)
		if err != nil {
			return nil, err
		}

		secret := k.factory()
		if err := secret.Unmarshal(i.Data); err != nil {
			return nil, err
		}
		creds[id] = secret
	}
	return creds, nil
}

func (k *keychainStore[T]) Save(ctx context.Context, id store.ID, secret store.Secret) error {
	if err := id.Valid(); err != nil {
		return err
	}

	data, err := secret.Marshal()
	if err != nil {
		return err
	}
	item := newKeychainItem(id.String(), k)
	item.SetData(data)
	// only creation of a secret needs the label attribute.
	// it is a user-friendly name for the item, which is displayed in the keychain UI.
	// https://developer.apple.com/documentation/security/ksecattrlabel
	item.SetLabel(k.itemLabel(id))
	return mapKeychainError(kc.AddItem(item))
}

func mapKeychainError(err error) error {
	if err == nil {
		return nil
	}
	switch err.Error() {
	case kc.ErrorInteractionNotAllowed.Error():
		return ErrInteractionNotAllowed
	case kc.ErrorItemNotFound.Error():
		return store.ErrCredentialNotFound
	case kc.ErrorAuthFailed.Error():
		return ErrAuthFailed
	}
	return err
}
