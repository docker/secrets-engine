package secrets

import (
	"errors"
	"time"
)

var ErrNotFound = errors.New("secret not found")

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
	GetSecret(request Request) (Envelope, error)
}
