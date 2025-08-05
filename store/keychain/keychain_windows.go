package keychain

import (
	"context"
	"errors"
	"iter"
	"maps"
	"strings"

	"github.com/danieljoos/wincred"
	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"

	"github.com/docker/secrets-engine/store"
)

var (
	ErrCredentialBadUsername      = errors.New("credential username is invalid")
	ErrInvalidCredentialFlags     = errors.New("an invalid flag was specified for the flags parameter")
	ErrInvalidCredentialParameter = errors.New("protected field does not match provided value for an existing credential")
	ErrNoLogonSession             = errors.New("logon session does not exist or there is no credential set associated with this logon session")
	sysErrInvalidCredentialFlags  = windows.ERROR_INVALID_FLAGS
	sysErrNoSuchLogonSession      = windows.ERROR_NO_SUCH_LOGON_SESSION
)

// encodeSecret marshals the secret into a slice of bytes in UTF16 format
func encodeSecret(secret store.Secret) ([]byte, error) {
	data, err := secret.Marshal()
	if err != nil {
		return nil, err
	}

	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	blob, _, err := transform.Bytes(encoder, data)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// decodeSecret unmarshals the secret from UTF16 format to UTF8
// secret will contain the unmarshaled value.
func decodeSecret(blob []byte, secret store.Secret) error {
	decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	val, _, err := transform.Bytes(decoder, blob)
	if err != nil {
		return err
	}

	return secret.Unmarshal(val)
}

func (k *keychainStore[T]) Delete(_ context.Context, id store.ID) error {
	g := wincred.NewGenericCredential(k.itemLabel(id.String()))
	err := g.Delete()
	if err != nil && !errors.Is(err, wincred.ErrElementNotFound) {
		return mapWindowsCredentialError(err)
	}
	return nil
}

func (k *keychainStore[T]) Get(_ context.Context, id store.ID) (store.Secret, error) {
	gc, err := wincred.GetGenericCredential(k.itemLabel(id.String()))
	if err != nil {
		return nil, mapWindowsCredentialError(err)
	}

	attributes := mapFromWindowsAttributes(gc.Attributes)
	safelyCleanMetadata(attributes)
	safelySetID(id, attributes)

	secret := k.factory()
	if err := secret.SetMetadata(attributes); err != nil {
		return nil, err
	}
	if err := decodeSecret(gc.CredentialBlob, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// isServiceCredential checks if a credential attribute contains the
// [serviceGroupKey] and [serviceNameKey] attribute.
//
// The keychainStore serviceGroup and serviceName should match what is stored
// in the attributes.
func isServiceCredential[T store.Secret](k *keychainStore[T], attrs []wincred.CredentialAttribute) bool {
	// must have both serviceGroup and serviceName
	var (
		serviceName  string
		serviceGroup string
	)
	for _, attr := range attrs {
		switch attr.Keyword {
		case serviceGroupKey:
			serviceGroup = string(attr.Value)
		case serviceNameKey:
			serviceName = string(attr.Value)
		}
	}
	return strings.EqualFold(serviceGroup, k.serviceGroup) && strings.EqualFold(serviceName, k.serviceName)
}

// findServiceCredentials is an iterator that yields credentials that match the
// service group and service name.
func findServiceCredentials[T store.Secret](k *keychainStore[T], pattern store.Pattern, credentials []*wincred.Credential) iter.Seq[*wincred.Credential] {
	return func(yield func(cred *wincred.Credential) bool) {
		for _, c := range credentials {
			if !isServiceCredential(k, c.Attributes) {
				continue
			}
			id, err := store.ParseID(c.UserName)
			if err != nil {
				continue
			}
			if !pattern.Match(id) {
				continue
			}
			if !yield(c) {
				return
			}
		}
	}
}

func mapToWindowsAttributes(attributes map[string]string) []wincred.CredentialAttribute {
	winAttrs := make([]wincred.CredentialAttribute, 0, len(attributes))
	for k, v := range attributes {
		winAttrs = append(winAttrs, wincred.CredentialAttribute{
			Keyword: k,
			Value:   []byte(v),
		})
	}
	return winAttrs
}

func mapFromWindowsAttributes(winAttrs []wincred.CredentialAttribute) map[string]string {
	attributes := make(map[string]string, len(winAttrs))
	for _, attr := range winAttrs {
		attributes[attr.Keyword] = string(attr.Value)
	}
	return attributes
}

func (k *keychainStore[T]) GetAllMetadata(context.Context) (map[string]store.Secret, error) {
	credentials, err := wincred.List()
	if err != nil {
		return nil, mapWindowsCredentialError(err)
	}

	onlyLabelPrefix := k.itemLabel("")

	// this pattern matches any secret ID that conforms to the secrets engine
	pattern := store.MustParsePattern("**")

	secrets := make(map[string]store.Secret)
	for cred := range findServiceCredentials(k, pattern, credentials) {
		id, err := store.ParseID(strings.ReplaceAll(cred.TargetName, onlyLabelPrefix, ""))
		if err != nil {
			return nil, err
		}

		attributes := mapFromWindowsAttributes(cred.Attributes)
		safelyCleanMetadata(attributes)

		secret := k.factory()
		if err := secret.SetMetadata(attributes); err != nil {
			return nil, err
		}
		secrets[id.String()] = secret
	}

	return secrets, nil
}

func (k *keychainStore[T]) Save(_ context.Context, id store.ID, secret store.Secret) error {
	blob, err := encodeSecret(secret)
	if err != nil {
		return err
	}

	attributes := make(map[string]string)
	maps.Copy(attributes, secret.Metadata())
	safelySetMetadata(k.serviceGroup, k.serviceName, attributes)
	safelySetID(id, attributes)

	g := wincred.NewGenericCredential(k.itemLabel(id.String()))
	g.UserName = id.String()
	g.CredentialBlob = blob
	g.Persist = wincred.PersistLocalMachine
	g.Attributes = mapToWindowsAttributes(attributes)
	return mapWindowsCredentialError(g.Write())
}

func (k *keychainStore[T]) Filter(_ context.Context, pattern store.Pattern) (map[string]store.Secret, error) {
	// Note: there is no notion of a filter on Windows inside the wincred API.
	// It has no way to even filter on known attributes.
	// This means we need to retrieve the entire list of ALL secrets, that
	// may or may not even be related to our serviceName, serviceGroup, or
	// keychain instance.
	// The performance of this shouldn't be too terrible as we don't fetch
	// the encrypted secret from the keychain unless it matches our pattern.

	credentials, err := wincred.List()
	if err != nil {
		return nil, mapWindowsCredentialError(err)
	}

	onlyLabelPrefix := k.itemLabel("")

	secrets := make(map[string]store.Secret)
	for cred := range findServiceCredentials(k, pattern, credentials) {
		id, err := store.ParseID(strings.ReplaceAll(cred.TargetName, onlyLabelPrefix, ""))
		if err != nil {
			continue
		}

		gc, err := wincred.GetGenericCredential(cred.TargetName)
		if err != nil {
			return nil, mapWindowsCredentialError(err)
		}

		decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		blob, _, err := transform.Bytes(decoder, gc.CredentialBlob)
		if err != nil {
			return nil, err
		}

		gcAttributes := mapFromWindowsAttributes(gc.Attributes)
		safelyCleanMetadata(gcAttributes)

		secret := k.factory()
		if err := secret.SetMetadata(gcAttributes); err != nil {
			return nil, err
		}
		if err := secret.Unmarshal(blob); err != nil {
			return nil, err
		}
		secrets[id.String()] = secret
	}

	return secrets, nil
}

func mapWindowsCredentialError(err error) error {
	switch err {
	case wincred.ErrElementNotFound:
		return store.ErrCredentialNotFound
	case wincred.ErrBadUsername:
		return ErrCredentialBadUsername
	case wincred.ErrInvalidParameter:
		return ErrInvalidCredentialParameter
	case sysErrInvalidCredentialFlags:
		return ErrInvalidCredentialFlags
	case sysErrNoSuchLogonSession:
		return ErrNoLogonSession
	}
	return err
}
