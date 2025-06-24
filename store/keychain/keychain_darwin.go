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

func (k *keychainStore[T]) getItem(id store.ID) kc.Item {
	item := kc.NewItem()
	// generic password is used here as we don't know what we are storing
	// the main difference between a generic and internet password is the
	// addition of a server URL
	item.SetSecClass(kc.SecClassGenericPassword)
	item.SetService(k.serviceName)
	item.SetAccessGroup(k.serviceGroup)
	item.SetMatchLimit(kc.MatchLimitOne)
	item.SetAccessible(kc.AccessibleAfterFirstUnlock)
	item.SetReturnData(true)
	item.SetReturnAttributes(true)
	if id.String() != "" {
		item.SetLabel(k.itemLabel(id))
		item.SetAccount(id.String())
	}
	return item
}

func (k *keychainStore[T]) Delete(ctx context.Context, id store.ID) error {
	return mapError(kc.DeleteItem(k.getItem(id)))
}

func (k *keychainStore[T]) Get(ctx context.Context, id store.ID) (store.Secret, error) {
	results, err := kc.QueryItem(k.getItem(id))
	if err != nil {
		return nil, mapError(err)
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
	item := k.getItem(store.ID(""))
	item.SetMatchLimit(kc.MatchLimitAll)
	results, err := kc.QueryItem(k.getItem(store.ID("")))
	if err != nil {
		return nil, mapError(err)
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
	item := k.getItem(id)
	item.SetData(data)
	return kc.AddItem(item)
}

func mapError(err error) error {
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
