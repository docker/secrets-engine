package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrNotFound     = errors.New("secret not found")
	ErrAccessDenied = errors.New("access denied") // nuh, uh, uh!
	ErrIDMismatch   = errors.New("id mismatch")
)

type Request struct {
	ID ID `json:"id"`

	// Provider can be optionally specified to restrict the resolver
	// to a particular provider stack.
	Provider    string    `json:"provider,omitempty"`
	ClientID    string    `json:"clientId,omitempty"`
	RequestedAt time.Time `json:"requestedAt"`
}

// request is a type alias to prevent recursive calls to MarshalJSON and UnmarshalJSON
type request Request

func (r *Request) MarshalJSON() ([]byte, error) {
	if err := r.Valid(); err != nil {
		return nil, err
	}
	return json.Marshal((*request)(r))
}

func (r *Request) UnmarshalJSON(b []byte) error {
	if r.ID == nil {
		r.ID = &id{}
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var tmp request
	if err := dec.Decode(&tmp); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("Request does not support more than one JSON object")
	}

	if err := (*Request)(&tmp).Valid(); err != nil {
		return err
	}

	*r = Request(tmp)
	return nil
}

func (r *Request) Valid() error {
	if r.ID == nil {
		return errors.New("ID must be set")
	}
	return nil
}

var (
	_ json.Marshaler   = &Request{}
	_ json.Unmarshaler = &Request{}
)

type Envelope struct {
	ID ID `json:"id"`
	// value will be base64 encoded
	Value      []byte    `json:"value,omitempty"`
	Provider   string    `json:"provider,omitempty"`
	Version    string    `json:"version,omitempty"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	ResolvedAt time.Time `json:"resolvedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

var (
	_ json.Marshaler   = &Envelope{}
	_ json.Unmarshaler = &Envelope{}
)

func (e *Envelope) Valid() error {
	if e.ID == nil {
		return errors.New("secrets.Envelope: `id` must be set")
	}
	if len(e.Value) == 0 {
		return errors.New("secrets.Envelope: `value` must be set")
	}
	if e.CreatedAt.IsZero() {
		return errors.New("secrets.Envelope: `createdAt` must be set")
	}
	return nil
}

// envelope is a type alias to avoid recursive calls to MarshalJSON and UnmarshalJSON
type envelope Envelope

func (e *Envelope) MarshalJSON() ([]byte, error) {
	if err := e.Valid(); err != nil {
		return nil, err
	}
	return json.Marshal((*envelope)(e))
}

func (e *Envelope) UnmarshalJSON(b []byte) error {
	if e == nil {
		return errors.New("secrets.Envelope: UnmarshalJSON on nil pointer")
	}

	if e.ID == nil {
		e.ID = &id{}
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	type rawID struct {
		ID json.RawMessage `json:"id"`
		envelope
	}
	var raw rawID
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("got an error decoding JSON into secrets.Envelope: %w", err)
	}

	if dec.More() {
		return errors.New("secrets.Envelope: does not support more than one JSON object")
	}

	id := &id{}
	if err := id.UnmarshalJSON(raw.ID); err != nil {
		return fmt.Errorf("secrets.Envelope could not decode secrets.ID: %v", err)
	}

	raw.envelope.ID = id
	envelope := Envelope(raw.envelope)

	if err := envelope.Valid(); err != nil {
		return err
	}

	*e = envelope

	return nil
}

type Resolver interface {
	GetSecret(ctx context.Context, request Request) (Envelope, error)
}

func EnvelopeErr(req Request, err error) Envelope {
	return Envelope{ID: req.ID, ResolvedAt: time.Now(), Error: err.Error()}
}
