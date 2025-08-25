package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound     = errors.New("secret not found")
	ErrAccessDenied = errors.New("access denied") // nuh, uh, uh!
	ErrIDMismatch   = errors.New("id mismatch")
)

type Request struct {
	Pattern Pattern `json:"-"`

	// Provider can be optionally specified to restrict the resolver
	// to a particular provider stack.
	Provider    string    `json:"-"`
	ClientID    string    `json:"-"`
	RequestedAt time.Time `json:"-"`
}

var _ json.Marshaler = Request{}

func (r Request) MarshalJSON() ([]byte, error) {
	panic("secrets.Request does not support json.Marshal")
}

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
	GetSecrets(ctx context.Context, request Request) ([]Envelope, error)
}
