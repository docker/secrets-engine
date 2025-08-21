package store

import (
	"context"

	"github.com/docker/secrets-engine/x/secrets"
)

type (
	ID      = secrets.ID
	Pattern = secrets.Pattern
)

var (
	ParseID          = secrets.ParseID
	MustParseID      = secrets.MustParseID
	ParsePattern     = secrets.ParsePattern
	MustParsePattern = secrets.MustParsePattern
)

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
	// Metadata returns a key-value pair of non-sensitive data about the secret
	Metadata() map[string]string
	// SetMetadata allows the caller to set the secrets non-sensitive data
	// A secret may expects certain keys or values from the map and may return
	// an error.
	SetMetadata(map[string]string) error
}

// Store defines a strict format for secrets to conform to when interacting
// with the secrets engine
type Store interface {
	// Delete removes credentials from the store for a given ID.
	Delete(ctx context.Context, id ID) error
	// Get retrieves credentials from the store for a given ID.
	Get(ctx context.Context, id ID) (Secret, error)
	// GetAllMetadata retrieves all the credentials from the store.
	// Credentials retrieved will only call [Secret.SetMetadata] so that the
	// underlying store does not get queried for each secret's sensitive data.
	// This could be very taxing on the underlying store and cause a poor User
	// Experience.
	GetAllMetadata(ctx context.Context) (map[string]Secret, error)
	// Save persists credentials from the store.
	Save(ctx context.Context, id ID, secret Secret) error
	// Filter returns a map of secrets based on a [Pattern].
	//
	// Secrets returned will have both [Secret.SetMetadata] and [Secret.Unmarshal]
	// called; in that order. Any error produced by any of them would result in
	// an early return with a nil secrets map.
	Filter(ctx context.Context, pattern Pattern) (map[string]Secret, error)
}
