package secretfile

import (
	"context"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

type (
	// PromptFunc is a callback function the store uses when a file is
	// encrypted/decrypted.
	PromptFunc func(context.Context) ([]byte, error)
)

type KeyType string

const (
	PasswordKeyType KeyType = "pass"
	AgeKeyType      KeyType = "age"
	SSHKeyType      KeyType = "ssh"
)

func getRecipient(k KeyType, encryptionKey string) (age.Recipient, error) {
	var recipient age.Recipient
	var err error

	switch k {
	case PasswordKeyType:
		recipient, err = age.NewScryptRecipient(encryptionKey)
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
// An error is returned if the key cannot be parsed or the key type is
// unsupported.
func GetRecipients(k KeyType, encryptionKeys []string) ([]age.Recipient, error) {
	var recipients []age.Recipient
	for _, encryptionKey := range encryptionKeys {
		recipient, err := getRecipient(k, encryptionKey)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

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
