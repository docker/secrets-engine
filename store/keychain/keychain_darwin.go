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

func newKeychainItem[T store.Secret](id store.ID, k *keychainStore[T]) kc.Item {
	item := kc.NewItem()
	// generic password is used here as we don't know what we are storing
	// the main difference between a generic and internet password is the
	// addition of a server URL
	item.SetSecClass(kc.SecClassGenericPassword)
	// MatchLimitOne is used to ensure we only get one item back when querying
	// set this to MatchLimitAll if you want to retrieve all items
	item.SetMatchLimit(kc.MatchLimitOne)
	item.SetAccessible(kc.AccessibleAfterFirstUnlock)
	item.SetReturnData(true)
	item.SetReturnAttributes(true)

	item.SetService(k.serviceName)
	item.SetAccessGroup(k.serviceGroup)

	if id.String() != "" {
		item.SetLabel(k.itemLabel(id))
		item.SetAccount(id.String())
	}

	return item
}

func (k *keychainStore[T]) Delete(ctx context.Context, id store.ID) error {
	item := newKeychainItem(id, k)
	return mapKeychainError(kc.DeleteItem(item))
}

func (k *keychainStore[T]) Get(ctx context.Context, id store.ID) (store.Secret, error) {
	item := newKeychainItem(id, k)
	results, err := kc.QueryItem(item)
	if err != nil {
		return nil, mapKeychainError(err)
	}
	if len(results) == 0 {
		return nil, store.ErrCredentialNotFound
	}

	secret := k.factory()
	if err := secret.Unmarshal(results[0].Data); err != nil {
		return nil, err
	}
	return secret, nil
}

func (k *keychainStore[T]) GetAll(ctx context.Context) (map[store.ID]store.Secret, error) {
	item := newKeychainItem(store.ID(""), k)
	item.SetMatchLimit(kc.MatchLimitAll)

	results, err := kc.QueryItem(item)
	if err != nil {
		return nil, mapKeychainError(err)
	}
	creds := make(map[store.ID]store.Secret, len(results))
	for _, result := range results {
		secret := k.factory()
		if err := secret.Unmarshal(result.Data); err != nil {
			return nil, err
		}
		id := store.ID(result.Label)
		creds[id] = secret
	}
	return creds, nil
}

func (k *keychainStore[T]) Save(ctx context.Context, id store.ID, secret store.Secret) error {
	data, err := secret.Marshal()
	if err != nil {
		return err
	}
	item := newKeychainItem(id, k)
	item.SetData(data)
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
