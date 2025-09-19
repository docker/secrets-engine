package keychain

import (
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/docker/secrets-engine/store"
)

type keychainStore[T store.Secret] struct {
	serviceGroup string
	serviceName  string
	factory      func() T
}

var _ store.Store = &keychainStore[store.Secret]{}

// New creates a new keychain store.
//
// It takes ServiceGroup and ServiceName and a [Factory] as input.
//
// A ServiceGroup is added to an item stored by the keychain under the item's
// attributes and label. Many applications can share the same serviceGroup.
//
// On macOS it is important that the service group matches the Keychain Access
// Groups. This prevents access from other applications not inside the Keychain
// Access group.
// https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps#Set-your-apps-access-groups
//
// On Linux the service group is added to the attributes of a secret to tag
// the item. The secrets service API does not have the concept of a scoped item
// per application inside the collection.
// Thus, adding a service group does not prevent other applications from
// accessing the secret.
//
// A ServiceName is a unique name of the application storing credentials, it is
// important to keep the service name unchanged once the service has stored credentials.
// Changing the service name can be done, but would require migrating existing credentials.
//
// [Factory] is a function used to instantiate new secrets of type T.
func New[T store.Secret](serviceGroup, serviceName string, factory store.Factory[T]) (store.Store, error) {
	if serviceGroup == "" || serviceName == "" {
		return nil, errors.New("serviceGroup and serviceName are required")
	}

	k := &keychainStore[T]{
		factory:      factory,
		serviceGroup: serviceGroup,
		serviceName:  serviceName,
	}
	return k, nil
}

// itemLabel prefixes a secret ID with the service group and service name
// e.g. group:name:id
func (k *keychainStore[T]) itemLabel(id string) string {
	return k.serviceGroup + ":" + k.serviceName + ":" + id
}

const (
	serviceGroupKey = "service:group"
	serviceNameKey  = "service:name"
	secretIDKey     = "id"
)

// safelySetMetadata is a helper function to keychain providers
// it adds internal metadata as well as prefixes externally defined attribute
// keys with `x_` so that no collissions can ever occur.
func safelySetMetadata(serviceGroup, serviceName string, attributes map[string]string) {
	// we need to collect all keys first otherwise we might double set the prefix
	keys := slices.Collect(maps.Keys(attributes))
	// prefix whatever is already in attributes
	for _, k := range keys {
		attributes["x_"+k] = attributes[k]
		delete(attributes, k)
	}

	attributes[serviceGroupKey] = serviceGroup
	attributes[serviceNameKey] = serviceName
}

// safelyCleanMetadata removes internal metadata and removes the `x_` prefix
// on all keys containing it.
func safelyCleanMetadata(attributes map[string]string) {
	delete(attributes, serviceGroupKey)
	delete(attributes, serviceNameKey)
	delete(attributes, secretIDKey)

	// we need to collect all keys first otherwise we might double set the prefix
	keys := slices.Collect(maps.Keys(attributes))
	for _, key := range keys {
		after, found := strings.CutPrefix(key, "x_")
		// this preserves metadata set by the caller.
		// we are restoring it by stripping the "x_" prefix.
		if found {
			attributes[after] = attributes[key]
		}
		// delete should always happen since we also want to remove attributes
		// there were never prefixed. In this case we are just dropping them
		// entirely. e.g. "xdg:scheme" set by the linux keychain internally.
		delete(attributes, key)
	}
}

// safelySetID stores the id inside the attributes
func safelySetID(id store.ID, attributes map[string]string) {
	// first check if the "id" key already exists, it's possibly set by the
	// caller, so we should avoid overwriting it.
	if v, ok := attributes[secretIDKey]; ok {
		attributes["x_"+secretIDKey] = v
	}
	attributes[secretIDKey] = id.String()
}
