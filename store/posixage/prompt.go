// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

type promptCaller interface {
	call(context.Context) ([]byte, error)
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

func getPromptCallerKeyType(f promptCaller) (secretfile.KeyType, error) {
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

// promptForEncryptionKeys invokes each registered [promptCaller]
// to collect encryption keys, grouped by their [secretfile.KeyType].
//
// Each callback is called in order. The returned key is trimmed of whitespace
// and validated to ensure it is not empty. Keys are then grouped into a map,
// where the map key is the callback's key type and the value is a slice of
// all collected keys for that type.
//
// It returns an error if any callback fails, if the key type cannot be
// determined, or if a callback returns an empty key.
func promptForEncryptionKeys(ctx context.Context, funcs []promptCaller) (map[secretfile.KeyType][]string, error) {
	m := map[secretfile.KeyType][]string{}
	for _, f := range funcs {
		groupType, err := getPromptCallerKeyType(f)
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
