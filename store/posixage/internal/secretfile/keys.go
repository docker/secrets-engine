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

package secretfile

import (
	"context"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

type (
	// PromptFunc is a callback invoked by the store when encrypting or
	// decrypting a file. The function is expected to return the key material
	// (as a byte slice) or an error if the key cannot be obtained.
	PromptFunc func(context.Context) ([]byte, error)

	// KeyType identifies the type of encryption or decryption key associated
	// with a secret (e.g., password, age, or SSH).
	KeyType string
)

const (
	PasswordKeyType KeyType = "pass"
	AgeKeyType      KeyType = "age"
	SSHKeyType      KeyType = "ssh"
)

// MaxScryptWorkFactor is the largest scrypt work factor (2^logN) that may be
// used when encrypting a password-protected secret. It matches the default
// maximum work factor accepted by age when decrypting, so files written at or
// below this value remain decryptable by standard age tooling.
const MaxScryptWorkFactor = 22

type recipientOptions struct {
	// scryptWorkFactor is the scrypt work factor (2^logN). A zero value means
	// the age default is used.
	scryptWorkFactor int
}

// RecipientOption configures how recipients are built by [GetRecipients].
type RecipientOption func(*recipientOptions)

// WithScryptWorkFactor sets the scrypt work factor (2^logN) used for
// [PasswordKeyType] recipients. It is a no-op for age and ssh key types.
//
// A zero value leaves the age default in place. Non-zero values are validated
// by [GetRecipients], which returns an error when logN is outside 1..[MaxScryptWorkFactor].
//
// See the posixage.WithScryptWorkFactor option for a cost/security table and
// guidance on choosing a value.
func WithScryptWorkFactor(logN int) RecipientOption {
	return func(o *recipientOptions) {
		o.scryptWorkFactor = logN
	}
}

func getRecipient(k KeyType, encryptionKey string, o *recipientOptions) (age.Recipient, error) {
	var recipient age.Recipient
	var err error

	switch k {
	case PasswordKeyType:
		var scryptRecipient *age.ScryptRecipient
		scryptRecipient, err = age.NewScryptRecipient(encryptionKey)
		if err == nil && o.scryptWorkFactor != 0 {
			if o.scryptWorkFactor < 1 || o.scryptWorkFactor > MaxScryptWorkFactor {
				return nil, fmt.Errorf("scrypt work factor out of range (1..%d): %d", MaxScryptWorkFactor, o.scryptWorkFactor)
			}
			scryptRecipient.SetWorkFactor(o.scryptWorkFactor)
		}
		recipient = scryptRecipient
	case AgeKeyType:
		recipient, err = age.ParseX25519Recipient(encryptionKey)
	case SSHKeyType:
		recipient, err = agessh.ParseRecipient(encryptionKey)
	default:
		return nil, fmt.Errorf("unsupported encryption type %T", k)
	}

	if err != nil {
		return nil, err
	}

	return recipient, nil
}

// GetRecipients returns a slice of [age.Recipient] for the given key type and
// encryption keys.
//
// The recipient implementation depends on the provided [KeyType]:
//   - passwordKeyType → [age.NewScryptRecipient]
//   - ageKeyType      → [age.ParseX25519Recipient]
//   - sshKeyType      → [agessh.ParseRecipient]
//
// Optional [RecipientOption] values tune recipient creation; see
// [WithScryptWorkFactor].
//
// An error is returned if the key cannot be parsed, an option is invalid, or
// the key type is unsupported.
func GetRecipients(k KeyType, encryptionKeys []string, opts ...RecipientOption) ([]age.Recipient, error) {
	o := &recipientOptions{}
	for _, opt := range opts {
		opt(o)
	}

	var recipients []age.Recipient
	for _, encryptionKey := range encryptionKeys {
		recipient, err := getRecipient(k, encryptionKey, o)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

// GetIdentity returns an [age.Identity] for the given key type and
// decryption key.
//
// The identity implementation depends on the provided [KeyType]:
//   - PasswordKeyType → [age.NewScryptIdentity]
//   - AgeKeyType      → [age.ParseX25519Identity]
//   - SSHKeyType      → [agessh.ParseIdentity]
//
// An error is returned if the key cannot be parsed or the key type is
// unsupported.
func GetIdentity(k KeyType, decryptionKey string) (age.Identity, error) {
	var identity age.Identity
	var err error

	switch k {
	case PasswordKeyType:
		identity, err = age.NewScryptIdentity(decryptionKey)
	case AgeKeyType:
		identity, err = age.ParseX25519Identity(decryptionKey)
	case SSHKeyType:
		identity, err = agessh.ParseIdentity([]byte(decryptionKey))
	default:
		return nil, fmt.Errorf("unsupported decryption type %T", k)
	}

	if err != nil {
		return nil, err
	}

	return identity, nil
}
