package secrets

import (
	"context"

	"github.com/docker/secrets-engine/pkg/secrets"
)

type ID = secrets.ID

var ParseID = secrets.ParseID

// Secret is a generic type that represents the actual secret values
//
// The implementer is responsible for defining the data structure of their secrets.
//
// Example:
//
//	type secret struct {
//		AccessToken string
//		RefreshToken string
//	}
//
//	func (s *secret) Marshal() ([]byte, error) {
//		return []byte(s.AccessToken+":"+s.RefreshToken), nil
//	}
//
//	func (s *secret) Unmarshal(data []byte) error {
//		tokens := bytes.Split(data, []byte(":"))
//		if len(tokens) != 2 {
//			return errors.New("invalid secret format")
//		}
//
//		s.AccessToken, s.RefreshToken = string(tokens[0]), string(tokens[1])
//		return nil
//	}
type Secret interface {
	// Marshal the secret into a slice of bytes
	Marshal() ([]byte, error)
	// Unmarshal the secret from a slice of bytes into its structured format
	Unmarshal(data []byte) error
}

// Store defines a strict format for secrets to conform to when interacting
// with the secrets engine
type Store interface {
	// Delete removes credentials from the store for a given ID.
	Delete(ctx context.Context, id ID) error
	// Get retrieves credentials from the store for a given ID.
	Get(ctx context.Context, id ID) (Secret, error)
	// GetAll retrieves all the credentials from the store.
	GetAll(ctx context.Context) (map[ID]Secret, error)
	// Save persists credentials from the store.
	Save(ctx context.Context, id ID, secret Secret) error
}
