package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ID contains a secret identifier.
// Valid secret identifiers must match the format [A-Za-z0-9.-]+(/[A-Za-z0-9.-]+)+?.
//
// For storage, we don't really differentiate much about the ID format but
// by convention we do simple, slash-separated management, providing a
// groupable access control system for management across plugins.
type ID interface {
	// String formats the [ID] as a string
	String() string
	// Match the [ID] against a [Pattern]
	Match(pattern Pattern) bool

	json.Unmarshaler
	json.Marshaler
}

type id struct {
	value string
}

func (id *id) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.value)
}

func (id *id) UnmarshalJSON(b []byte) error {
	var s string
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("secrets.ID does not support more than one JSON object")
	}
	if err := valid(s); err != nil {
		return err
	}
	id.value = s
	return nil
}

// NewID creates a new [ID] from a string
// If a validation error occurs, it returns nil and the error.
func NewID(s string) (ID, error) {
	if err := valid(s); err != nil {
		return nil, fmt.Errorf("parsing id: %w", err)
	}
	return &id{
		value: s,
	}, nil
}

// MustNewID creates a new ID as [NewID] does, but panics when a validation
// error occurs.
func MustNewID(s string) ID {
	if err := valid(s); err != nil {
		panic(err)
	}
	return &id{
		value: s,
	}
}

// Valid returns nil if the identifier is considered valid.
func valid(id string) error {
	if !validIdentifier(id) {
		return fmt.Errorf("invalid identifier: %q must match [A-Za-z0-9.-]+(/[A-Za-z0-9.-]+)*?", id)
	}

	return nil
}

func (id *id) String() string { return id.value }

// validIdentifier checks if an identifier is valid without using regexp or unicode.
// Rules:
// - Components separated by '/'
// - Each component is non-empty
// - Only characters A-Z, a-z, 0-9, '.', '_' or '-'
// - No leading, trailing, or double slashes
func validIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}

	componentLen := 0

	for _, r := range s {
		switch {
		case r == '/':
			if componentLen == 0 {
				// Empty component (leading, trailing, or double slash)
				return false
			}
			componentLen = 0
		case isValidRune(r):
			componentLen++
		default:
			return false
		}
	}

	// Final component must not be empty
	return componentLen > 0
}

func isValidRune(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '.' || c == '-' || c == '_'
}

// Match checks if a given identifier matches the pattern.
// - "*" matches a single component
// - "**" matches zero or more components
// - "/" is the separator
func (id *id) Match(pattern Pattern) bool {
	pathParts := split(id.value)
	patternParts := split(pattern.String())

	return match(patternParts, pathParts)
}

func split(s string) []string {
	s = strings.Trim(s, "/")
	if s == "" {
		return []string{}
	}
	return strings.Split(s, "/")
}

func match(pattern, path []string) bool {
	pi, si := 0, 0
	for pi < len(pattern) && si < len(path) {
		switch pattern[pi] {
		case "**":
			// Try to consume any number of path segments
			if pi+1 == len(pattern) {
				return true // trailing ** matches rest
			}
			// Try to find a match for the rest of the pattern
			for skip := 0; si+skip <= len(path); skip++ {
				if match(pattern[pi+1:], path[si+skip:]) {
					return true
				}
			}
			return false
		case "*":
			// Match exactly one path component
			pi++
			si++
		default:
			if pattern[pi] != path[si] {
				return false
			}
			pi++
			si++
		}
	}

	// Handle trailing pattern parts (like **)
	for pi < len(pattern) && pattern[pi] == "**" {
		pi++
	}

	return pi == len(pattern) && si == len(path)
}
