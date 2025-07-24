package examples

import (
	"bytes"
	"errors"

	secrets "github.com/docker/secrets-engine/store"
)

type secret struct {
	AccessToken  string
	RefreshToken string
	Attributes   map[string]string
}

// Metadata implements store.Secret.
func (s *secret) Metadata() map[string]string {
	return s.Attributes
}

// SetMetadata implements store.Secret.
func (s *secret) SetMetadata(attributes map[string]string) error {
	s.Attributes = attributes
	return nil
}

var _ secrets.Secret = &secret{}

func (s *secret) Marshal() ([]byte, error) {
	return []byte(s.AccessToken + ":" + s.RefreshToken), nil
}

func (s *secret) Unmarshal(data []byte) error {
	tokens := bytes.Split(data, []byte(":"))
	if len(tokens) != 2 {
		return errors.New("invalid secret format")
	}

	s.AccessToken, s.RefreshToken = string(tokens[0]), string(tokens[1])
	return nil
}
