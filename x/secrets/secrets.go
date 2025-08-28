package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

var (
	ErrNotFound     = errors.New("secret not found")
	ErrAccessDenied = errors.New("access denied") // nuh, uh, uh!
)

type Envelope struct {
	ID         ID        `json:"-"`
	Value      []byte    `json:"-"`
	Provider   string    `json:"-"`
	Version    string    `json:"-"`
	CreatedAt  time.Time `json:"-"`
	ResolvedAt time.Time `json:"-"`
	ExpiresAt  time.Time `json:"-"`
}

var _ json.Marshaler = Envelope{}

func (e Envelope) MarshalJSON() ([]byte, error) {
	panic("secrets.Envelope does not support json.Marshal")
}

type Resolver interface {
	GetSecrets(ctx context.Context, pattern Pattern) ([]Envelope, error)
}

type Authenticator interface {
	Authenticate(ctx context.Context, pattern Pattern, header http.Header) error
}
