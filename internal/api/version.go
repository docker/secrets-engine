package api

import (
	"errors"
	"fmt"

	"golang.org/x/mod/semver"
)

var (
	ErrEmptyVersion = errors.New("empty version")
	ErrVPrefix      = errors.New("redundant version prefix")
)

type Version interface {
	String() string
}

type version struct {
	value string
}

func (v *version) String() string {
	return v.value
}

// NewVersion creates a new [Version] from a string
// If a validation error occurs, it returns nil and the error.
func NewVersion(s string) (Version, error) {
	if err := valid(s); err != nil {
		return nil, fmt.Errorf("parsing version: %w", err)
	}
	return &version{
		value: s,
	}, nil
}

// MustNewVersion creates a new Version as [NewVersion] does, but panics when a validation
// error occurs.
func MustNewVersion(s string) Version {
	v, err := NewVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}

func valid(s string) error {
	if len(s) > 0 && s[0] == 'v' {
		return ErrVPrefix
	}
	if s == "" {
		return ErrEmptyVersion
	}
	if !semver.IsValid("v" + s) {
		return fmt.Errorf("invalid version: %s", s)
	}
	return nil
}
