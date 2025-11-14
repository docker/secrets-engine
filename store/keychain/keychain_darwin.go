package keychain

import (
	"context"
	"errors"
	"fmt"
	"maps"

	kc "github.com/docker/secrets-engine/store/keychain/internal/go-keychain"

	"github.com/docker/secrets-engine/store"
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
	item.SetUseDataProtectionKeychain(kc.UseDataProtectionKeychainYes)

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

func convertAttributes(attributes map[string]any) (map[string]string, error) {
	attr := make(map[string]string, len(attributes))
	for k, v := range attributes {
		switch t := v.(type) {
		case string:
			attr[k] = t
		default:
			return nil, fmt.Errorf("attributes of key %s has unsupported type %T", k, t)
		}
	}
	return attr, nil
}

func (k *keychainStore[T]) Delete(_ context.Context, id store.ID) error {
	item := newKeychainItem(id.String(), k)
	err := kc.DeleteItem(item)
	if err != nil && !errors.Is(err, kc.ErrorItemNotFound) {
		return mapKeychainError(err)
	}
	return nil
}

func (k *keychainStore[T]) Get(_ context.Context, id store.ID) (store.Secret, error) {
	result, err := getItemWithData(id.String(), k)
	if err != nil {
		return nil, err
	}

	attributes, err := convertAttributes(result.Attributes)
	if err != nil {
		return nil, err
	}
	safelyCleanMetadata(attributes)

	secret := k.factory()
	if err := secret.SetMetadata(attributes); err != nil {
		return nil, err
	}
	if err := secret.Unmarshal(result.Data); err != nil {
		return nil, err
	}
	return secret, nil
}

func (k *keychainStore[T]) GetAllMetadata(context.Context) (map[store.ID]store.Secret, error) {
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
		attributes, err := convertAttributes(result.Attributes)
		if err != nil {
			return nil, err
		}
		safelyCleanMetadata(attributes)

		secret := k.factory()
		if err := secret.SetMetadata(attributes); err != nil {
			return nil, err
		}
		creds[id] = secret
	}
	return creds, nil
}

func (k *keychainStore[T]) Save(_ context.Context, id store.ID, secret store.Secret) error {
	data, err := secret.Marshal()
	if err != nil {
		return err
	}
	item := newKeychainItem(id.String(), k)
	item.SetData(data)
	// only creation of a secret needs the label attribute.
	// it is a user-friendly name for the item, which is displayed in the keychain UI.
	// https://developer.apple.com/documentation/security/ksecattrlabel
	item.SetLabel(k.itemLabel(id.String()))

	metadata := make(map[string]string)
	maps.Copy(metadata, secret.Metadata())
	safelySetMetadata(k.serviceGroup, k.serviceName, metadata)
	safelySetID(id, metadata)

	metadataAny := make(map[string]any)
	for k, v := range metadata {
		metadataAny[k] = v
	}
	item.SetGenericMetadata(metadataAny)

	return mapKeychainError(kc.AddItem(item))
}

func (k *keychainStore[T]) Filter(_ context.Context, pattern store.Pattern) (map[store.ID]store.Secret, error) {
	// Note: Filter on macOS cannot filter by generic attributes and thus we
	// cannot split the ID and store it in the keychain as parts for later
	// pattern matching.
	// We only have access to:
	// - "Account" (secrets.ID)
	// - "ServiceName" this keychain instances' serviceName
	// - "ServiceGroup" this keychain instances' serviceGroup
	//
	// Filtering happens after we have retrieved the secrets from the store
	// based on the above attributes.
	// We then match the IDs against the pattern, 1 by 1.
	// This shouldn't be too expensive since we don't actually retrieve the
	// encrypted secret when fetching many secrets. Only after they match
	// the pattern, do we fetch their data and possibly prompt the user.

	item := newKeychainItem("", k)

	// We use the MatchLimitAll attribute to query for multiple items from the
	// store. It cannot be used with item.SetReturnData.
	// https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)#Discussion
	item.SetMatchLimit(kc.MatchLimitAll)

	results, err := kc.QueryItem(item)
	if err != nil {
		return nil, mapKeychainError(err)
	}

	creds := make(map[store.ID]store.Secret)
	for _, result := range results {
		// it is possible that someone else has stored secrets in the keychain
		// directly without conforming to the store.ID format.
		// We shouldn't error here when these values cannot be retrieved or
		// parsed. Instead we just ignore them and proceed.
		// I guess in future we could at least log them somewhere?
		// but for now, let's just continue with the other items in the store.
		id, err := store.ParseID(result.Account)
		if err != nil {
			continue
		}

		// filter out any secrets based on the pattern which we couldn't do
		// with the keychain API
		if !pattern.Match(id) {
			continue
		}

		attr, err := convertAttributes(result.Attributes)
		if err != nil {
			return nil, err
		}
		safelyCleanMetadata(attr)

		i, err := getItemWithData(id.String(), k)
		if err != nil {
			return nil, err
		}

		secret := k.factory()
		if err := secret.SetMetadata(attr); err != nil {
			return nil, err
		}
		if err := secret.Unmarshal(i.Data); err != nil {
			return nil, err
		}
		creds[id] = secret
	}

	return creds, nil
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
