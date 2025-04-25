package main

import (
	"errors"
)

var ErrNotFound = errors.New("secret not found")

type SecretProvider interface {
	GetSecret(id ID) (Envelope, error)
}
