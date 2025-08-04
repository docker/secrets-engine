package api

import (
	"errors"
	"fmt"
)

var ErrEmptyName = errors.New("empty name")

type Name interface {
	String() string
}

type name struct {
	value string
}

func (n *name) String() string {
	return n.value
}

// NewName creates a new [Name] from a string
// If a validation error occurs, it returns nil and the error.
func NewName(s string) (Name, error) {
	if err := validName(s); err != nil {
		return nil, fmt.Errorf("parsing name: %w", err)
	}
	return &name{
		value: s,
	}, nil
}

// MustNewName creates a new Name as [NewName] does, but panics when a validation
// error occurs.
func MustNewName(s string) Name {
	v, err := NewName(s)
	if err != nil {
		panic(err)
	}
	return v
}

func validName(s string) error {
	if s == "" {
		return ErrEmptyName
	}
	return nil
}
