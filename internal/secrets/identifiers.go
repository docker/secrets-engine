package secrets

import (
	"fmt"
	"strings"
)

// ID contains a secret identifier.
// Valid secret identifiers must match the format [A-Za-z0-9.-]+(/[A-Za-z0-9.-]+)+?.
//
// For storage, we don't really differentiate much about the ID format but
// by convention we do simple, slash-separated management, providing a
// groupable access control system for management across plugins.
type ID string

func ParseID(s string) (ID, error) {
	id := ID(s)
	if err := id.Valid(); err != nil {
		return "", fmt.Errorf("parsing id: %w", err)
	}

	return id, nil
}

// Valid returns nil if the identifier is considered valid.
func (id ID) Valid() error {
	if !validIdentifier(string(id)) {
		return fmt.Errorf("invalid identifier: %q must match [A-Za-z0-9.-]+(/[A-Za-z0-9.-]+)*?", id)
	}

	return nil
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
