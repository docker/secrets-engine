package keychain

import (
	"context"
	"errors"
	"iter"
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
	sysErrInvalidCredentialFlags  = windows.Errno(windows.ERROR_INVALID_FLAGS)
	sysErrNoSuchLogonSession      = windows.Errno(windows.ERROR_NO_SUCH_LOGON_SESSION)
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

func (k *keychainStore[T]) Delete(ctx context.Context, id store.ID) error {
	if err := id.Valid(); err != nil {
		return err
	}

	g := wincred.NewGenericCredential(k.itemLabel(id))
	err := g.Delete()
	if err != nil && !errors.Is(err, wincred.ErrElementNotFound) {
		return mapWindowsCredentialError(err)
	}
	return nil
}

func (k *keychainStore[T]) Get(ctx context.Context, id store.ID) (store.Secret, error) {
	if err := id.Valid(); err != nil {
		return nil, err
	}

	gc, err := wincred.GetGenericCredential(k.itemLabel(id))
	if err != nil {
		return nil, mapWindowsCredentialError(err)
	}

	secret := k.factory()
	if err := decodeSecret(gc.CredentialBlob, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// isServiceCredential checks if a credential attribute contains the
// `service:group` and `service:name` attribute.
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
		case "service:group":
			serviceGroup = string(attr.Value)
		case "service:name":
			serviceName = string(attr.Value)
		}
	}
	return strings.EqualFold(serviceGroup, k.serviceGroup) && strings.EqualFold(serviceName, k.serviceName)
}

// findServiceCredentials is an iterator that yields credentials that match the
// service group and service name.
func findServiceCredentials[T store.Secret](k *keychainStore[T], credentials []*wincred.Credential) iter.Seq[*wincred.Credential] {
	return func(yield func(cred *wincred.Credential) bool) {
		for _, c := range credentials {
			if isServiceCredential(k, c.Attributes) {
				if !yield(c) {
					return
				}
			}
		}
	}
}

func (k *keychainStore[T]) GetAll(ctx context.Context) (map[store.ID]store.Secret, error) {
	credentials, err := wincred.List()
	if err != nil {
		return nil, mapWindowsCredentialError(err)
	}

	onlyLabelPrefix := k.itemLabel(store.ID(""))

	secrets := make(map[store.ID]store.Secret, len(credentials))
	for cred := range findServiceCredentials(k, credentials) {
		secret := k.factory()
		id, err := store.ParseID(strings.ReplaceAll(cred.TargetName, onlyLabelPrefix, ""))
		if err != nil {
			return nil, err
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
		if err := secret.Unmarshal(blob); err != nil {
			return nil, err
		}
		secrets[id] = secret
	}

	return secrets, nil
}

func (k *keychainStore[T]) Save(ctx context.Context, id store.ID, secret store.Secret) error {
	if err := id.Valid(); err != nil {
		return err
	}

	blob, err := encodeSecret(secret)
	if err != nil {
		return err
	}

	g := wincred.NewGenericCredential(k.itemLabel(id))
	g.UserName = id.String()
	g.CredentialBlob = blob
	g.Persist = wincred.PersistLocalMachine
	g.Attributes = []wincred.CredentialAttribute{
		{
			Keyword: "id",
			Value:   []byte(id.String()),
		},
		{
			Keyword: "service:group",
			Value:   []byte(k.serviceGroup),
		},
		{
			Keyword: "service:name",
			Value:   []byte(k.serviceName),
		},
	}
	return mapWindowsCredentialError(g.Write())
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
