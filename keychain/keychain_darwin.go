//go:build darwin && cgo

package keychain

import (
	"context"

	kc "github.com/keybase/go-keychain"
)

const (
	ServiceName  = "DockerAuth"
	ServiceGroup = "com.docker.auth"
)

func getItem(id ID) kc.Item {
	item := kc.NewItem()
	item.SetSecClass(kc.SecClassGenericPassword)
	item.SetService(ServiceName)
	item.SetAccessGroup(ServiceGroup)
	item.SetMatchLimit(kc.MatchLimitOne)
	item.SetAccessible(kc.AccessibleAfterFirstUnlock)
	item.SetReturnData(true)
	item.SetReturnAttributes(true)
	item.SetLabel(id.String())
	item.SetAccount(id.String())
	return item
}

func (k *keychainStore[T]) Erase(ctx context.Context, id ID) error {
	return mapError(kc.DeleteItem(getItem(id)))
}

func (k *keychainStore[T]) Get(ctx context.Context, id ID) (Secret, error) {
	results, err := kc.QueryItem(getItem(id))
	if err != nil {
		return nil, mapError(err)
	}
	if len(results) == 0 {
		return nil, ErrCredentialsNotFound
	}

	secret := k.factory()
	if err := secret.Unmarshal(results[0].Data); err != nil {
		return nil, err
	}
	return secret, nil
}

func (k *keychainStore[T]) GetAll(ctx context.Context) (map[ID]Secret, error) {
	item := getItem(ID(""))
	item.SetMatchLimit(kc.MatchLimitAll)
	results, err := kc.QueryItem(getItem(ID("")))
	if err != nil {
		return nil, mapError(err)
	}
	creds := make(map[ID]Secret, len(results))
	for _, result := range results {
		secret := k.factory()
		if err := secret.Unmarshal(result.Data); err != nil {
			return nil, err
		}
		id := ID(result.Label)
		creds[id] = secret
	}
	return creds, nil
}

func (k *keychainStore[T]) Store(ctx context.Context, id ID, secret Secret) error {
	data, err := secret.Marshal()
	if err != nil {
		return err
	}
	item := getItem(id)
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
		return ErrCredentialsNotFound
	case kc.ErrorAuthFailed.Error():
		return ErrAuthFailed
	}
	return err
}
