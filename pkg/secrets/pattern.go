package secrets

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidPattern = errors.New("invalid pattern")
)

type Pattern string

func ParsePattern(pattern string) (Pattern, error) {
	p := Pattern(pattern)
	if err := p.Valid(); err != nil {
		return "", fmt.Errorf("parse pattern: %w", err)
	}
	return p, nil
}

func (p Pattern) Valid() error {
	if !validPattern(string(p)) {
		return ErrInvalidPattern
	}
	return nil
}

func (p Pattern) Match(id ID) bool {
	pathParts := split(string(id))
	patternParts := split(string(p))

	return match(patternParts, pathParts)
}

// validPattern checks if a pattern is valid without using regexp or unicode.
// Rules:
// - Components separated by '/'
// - Each component is non-empty
// - Only characters A-Z, a-z, 0-9, '.', '-', '_' or '*'
// - No leading, trailing, or double slashes
// - '*' can be used in two ways: '*' matches a single component, '**' matches zero or more components
func validPattern(s string) bool {
	if len(s) == 0 {
		return false
	}

	componentLen := 0
	wildcardLen := 0
	for _, r := range s {
		switch {
		case r == '/':
			if componentLen == 0 {
				// Empty component (leading, trailing, or double slash)
				return false
			}
			if wildcardLen > 2 {
				// No more than two wildcards per component
				return false
			}
			if wildcardLen > 0 && wildcardLen != componentLen {
				// Wildcard can't be mixed with other characters in the same component
				return false
			}
			componentLen = 0
			wildcardLen = 0
		case isValidPatternRune(r):
			componentLen++
			if r == '*' {
				wildcardLen++
			}
		default:
			return false
		}
	}

	// Final component must not be empty
	return componentLen > 0
}

func isValidPatternRune(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '.' || c == '-' || c == '_' || c == '*'
}
