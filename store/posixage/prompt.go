package posixage

import (
	"bytes"
	"context"
	"errors"

	"github.com/docker/secrets-engine/store/posixage/internal/secretfile"
)

type (
	EncryptionPassword  secretfile.PromptFunc
	EncryptionAgeX25519 secretfile.PromptFunc
	// EncryptionSSH supports ssh-rsa and ssh-ed25519
	EncryptionSSH secretfile.PromptFunc

	// DecryptionAgeX25519 is the age private key
	DecryptionAgeX25519 secretfile.PromptFunc
	// DecryptionSSH is the ssh private key
	DecryptionSSH      secretfile.PromptFunc
	DecryptionPassword secretfile.PromptFunc
)

func (ep EncryptionPassword) Call(ctx context.Context) ([]byte, error) {
	return ep(ctx)
}

func (ea EncryptionAgeX25519) Call(ctx context.Context) ([]byte, error) {
	return ea(ctx)
}

func (es EncryptionSSH) Call(ctx context.Context) ([]byte, error) {
	return es(ctx)
}

func (da DecryptionAgeX25519) Call(ctx context.Context) ([]byte, error) {
	return da(ctx)
}

func (ds DecryptionSSH) Call(ctx context.Context) ([]byte, error) {
	return ds(ctx)
}

func (dp DecryptionPassword) Call(ctx context.Context) ([]byte, error) {
	return dp(ctx)
}

func getPromptCallerKeyType(f secretfile.PromptCaller) (secretfile.KeyType, error) {
	switch f.(type) {
	case EncryptionPassword:
		return secretfile.PasswordKeyType, nil
	case EncryptionAgeX25519:
		return secretfile.AgeKeyType, nil
	case EncryptionSSH:
		return secretfile.SSHKeyType, nil
	case DecryptionPassword:
		return secretfile.PasswordKeyType, nil
	case DecryptionAgeX25519:
		return secretfile.AgeKeyType, nil
	case DecryptionSSH:
		return secretfile.SSHKeyType, nil
	default:
		return "", errors.New("invalid callback function type")
	}
}

// promptForEncryptionKeys invokes each registered [secretfile.PromptCaller]
// to collect encryption keys, grouped by their [secretfile.KeyType].
//
// Each callback is called in order. The returned key is trimmed of whitespace
// and validated to ensure it is not empty. Keys are then grouped into a map,
// where the map key is the callback's key type and the value is a slice of
// all collected keys for that type.
//
// It returns an error if any callback fails, if the key type cannot be
// determined, or if a callback returns an empty key.
func promptForEncryptionKeys(ctx context.Context, funcs []secretfile.PromptCaller) (map[secretfile.KeyType][]string, error) {
	m := map[secretfile.KeyType][]string{}
	for _, f := range funcs {
		groupType, err := getPromptCallerKeyType(f)
		if err != nil {
			return nil, err
		}

		raw, err := f.Call(ctx)
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
