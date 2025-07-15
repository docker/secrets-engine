package secrets

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound     = errors.New("secret not found")
	ErrAccessDenied = errors.New("access denied") // nuh, uh, uh!
	ErrIDMismatch   = errors.New("id mismatch")
)

type Request struct {
	ID ID `json:",omitzero"`

	// Provider can be optionally specified to restrict the resolver
	// to a particular provider stack.
	Provider    string `json:",omitzero"`
	ClientID    string `json:",omitzero"`
	RequestedAt time.Time
}

type Envelope struct {
	ID         ID
	Value      []byte    `json:",omitzero"`
	Provider   string    `json:",omitzero"`
	Version    string    `json:",omitzero"`
	Error      string    `json:",omitzero"`
	CreatedAt  time.Time `json:",omitzero"`
	ResolvedAt time.Time `json:",omitzero"`
	ExpiresAt  time.Time `json:",omitzero"`
}

type Resolver interface {
	GetSecret(ctx context.Context, request Request) (Envelope, error)
}

func EnvelopeErr(req Request, err error) Envelope {
	return Envelope{ID: req.ID, ResolvedAt: time.Now(), Error: err.Error()}
}
