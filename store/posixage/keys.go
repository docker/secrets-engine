package posixage

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

type (
	// keyCallbackFunc is a callback function the store uses when a file is
	// encrypted/decrypted.
	keyCallbackFunc func(context.Context) ([]byte, error)

	EncryptionPassword  keyCallbackFunc
	EncryptionAgeX25519 keyCallbackFunc
	// EncryptionSSH supports ssh-rsa and ssh-ed25519
	EncryptionSSH keyCallbackFunc

	// DecryptionAgeX25519 is the age private key
	DecryptionAgeX25519 keyCallbackFunc
	// DecryptionSSH is the ssh private key
	DecryptionSSH      keyCallbackFunc
	DecryptionPassword keyCallbackFunc
)

type callbackFunc interface {
	call(context.Context) ([]byte, error)
}

func getCallbackFuncName(f callbackFunc) (keyType, error) {
	switch f.(type) {
	case EncryptionPassword:
		return passwordKeyType, nil
	case EncryptionAgeX25519:
		return ageKeyType, nil
	case EncryptionSSH:
		return sshKeyType, nil
	case DecryptionPassword:
		return passwordKeyType, nil
	case DecryptionAgeX25519:
		return ageKeyType, nil
	case DecryptionSSH:
		return sshKeyType, nil
	default:
		return "", errors.New("invalid callback function type")
	}
}

func (k keyCallbackFunc) call(ctx context.Context) ([]byte, error) {
	return k(ctx)
}

func (ep EncryptionPassword) call(ctx context.Context) ([]byte, error) {
	return ep(ctx)
}

func (ea EncryptionAgeX25519) call(ctx context.Context) ([]byte, error) {
	return ea(ctx)
}

func (es EncryptionSSH) call(ctx context.Context) ([]byte, error) {
	return es(ctx)
}

func (da DecryptionAgeX25519) call(ctx context.Context) ([]byte, error) {
	return da(ctx)
}

func (ds DecryptionSSH) call(ctx context.Context) ([]byte, error) {
	return ds(ctx)
}

func (dp DecryptionPassword) call(ctx context.Context) ([]byte, error) {
	return dp(ctx)
}

type keyType string

const (
	passwordKeyType keyType = "pass"
	ageKeyType      keyType = "age"
	sshKeyType      keyType = "ssh"
)

func getRecipient(g keyType, value string) (age.Recipient, error) {
	var recipient age.Recipient
	var err error

	switch g {
	case passwordKeyType:
		recipient, err = age.NewScryptRecipient(value)
	case ageKeyType:
		recipient, err = age.ParseX25519Recipient(value)
	case sshKeyType:
		recipient, err = agessh.ParseRecipient(value)
	default:
		return nil, fmt.Errorf("unsupported encryption type %T", g)
	}

	if err != nil {
		return nil, err
	}

	return recipient, nil
}

func getIdentity(g keyType, value string) (age.Identity, error) {
	var identity age.Identity
	var err error

	switch g {
	case passwordKeyType:
		identity, err = age.NewScryptIdentity(value)
	case ageKeyType:
		identity, err = age.ParseX25519Identity(value)
	case sshKeyType:
		identity, err = agessh.ParseIdentity([]byte(value))
	default:
		return nil, fmt.Errorf("unsupported decryption type %T", g)
	}

	if err != nil {
		return nil, err
	}

	return identity, nil
}

// groupCallbackFuncs groups callback functions by their type.
//
// It returns a map where the key is the callback function type and the value
// is a slice of strings representing the associated callback values.
func groupCallbackFuncs(ctx context.Context, funcs []callbackFunc) (map[keyType][]string, error) {
	m := map[keyType][]string{}
	for _, f := range funcs {
		groupType, err := getCallbackFuncName(f)
		if err != nil {
			return nil, err
		}

		raw, err := f.call(ctx)
		if err != nil {
			return nil, err
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			return nil, errors.New("empty key provided on registered callback function")
		}
		m[groupType] = append(m[groupType], string(raw))
	}
	return m, nil
}
