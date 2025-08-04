package secrets

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ErrInvalidID struct {
	id string
}

func (e ErrInvalidID) Error() string {
	return fmt.Sprintf("invalid identifier: %q must match [A-Za-z0-9.-]+(/[A-Za-z0-9.-]+)*?", e.id)
}

// ID contains a secret identifier.
// Valid secret identifiers must match the format [A-Za-z0-9.-]+(/[A-Za-z0-9.-]+)+?.
//
// For storage, we don't really differentiate much about the ID format but
// by convention we do simple, slash-separated management, providing a
// groupable access control system for management across plugins.
//
// Deprecated: Use [IDNew] instead
type ID string

func ParseID(s string) (ID, error) {
	id := ID(s)
	if err := id.Valid(); err != nil {
		return "", err
	}

	return id, nil
}

// Valid returns nil if the identifier is considered valid.
func (id ID) Valid() error {
	return valid(id.String())
}

func (id ID) String() string { return string(id) }

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
func (id ID) Match(pattern Pattern) bool {
	pathParts := split(string(id))
	patternParts := split(string(pattern))

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

func valid(id string) error {
	if !validIdentifier(id) {
		return ErrInvalidID{
			id: id,
		}
	}

	return nil
}

// IDNew contains a secret identifier.
// Valid secret identifiers must match the format [A-Za-z0-9.-]+(/[A-Za-z0-9.-]+)+?.
//
// For storage, we don't really differentiate much about the IDNew format but
// by convention we do simple, slash-separated management, providing a
// groupable access control system for management across plugins.
type IDNew interface {
	// String formats the [IDNew] as a string
	String() string
	// Match the [IDNew] against a [PatternNew]
	// It checks if a given identifier matches the pattern.
	// - "*" matches a single component
	// - "**" matches zero or more components
	// - "/" is the separator
	Match(pattern PatternNew) bool

	json.Marshaler
	json.Unmarshaler
}

type id struct {
	value string
}

func (i *id) Match(pattern PatternNew) bool {
	pathParts := split(i.value)
	patternParts := split(pattern.String())

	return match(patternParts, pathParts)
}

func (i *id) String() string {
	return i.value
}

func (i *id) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.value)
}

func (i *id) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if err := valid(s); err != nil {
		return err
	}
	i.value = s
	return nil
}

var _ IDNew = &id{}

// ParseIDNew creates a new [IDNew] from a string
// If a validation error occurs, it returns nil and the error.
// Rules:
// - Components separated by '/'
// - Each component is non-empty
// - Only characters A-Z, a-z, 0-9, '.', '_' or '-'
// - No leading, trailing, or double slashes
func ParseIDNew(s string) (IDNew, error) {
	if err := valid(s); err != nil {
		return nil, err
	}

	return &id{
		value: s,
	}, nil
}

// MustParseIDNew parses a string into a [IDNew] and behaves similar to
// [ParseIDNew], however, it panics when the id is invalid
func MustParseIDNew(s string) IDNew {
	if err := valid(s); err != nil {
		panic(err)
	}
	return &id{
		value: s,
	}
}
