package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
)

var ErrInvalidPattern = errors.New("invalid pattern")

// Pattern can be used to match secret identifiers.
// Valid patterns must follow the same validation rules as secret identifiers, with the exception
// that '*' can be used to match a single component, and '**' can be used to match zero or more components.
//
// Deprecated: Use [PatternNew] instead
type Pattern string

func ParsePattern(pattern string) (Pattern, error) {
	p := Pattern(pattern)
	if err := p.Valid(); err != nil {
		return "", fmt.Errorf("parsing pattern: %w", err)
	}
	return p, nil
}

// Valid returns nil if the pattern is considered valid.
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
// - Asterisks rules:
//   - '*' cannot be mixed with other characters in the same component
//   - there can be no more than two '*' per component
func validPattern(s string) bool {
	if len(s) == 0 {
		return false
	}

	componentLen := 0
	wildcardLen := 0

	for _, r := range s {
		switch {
		case r == '/':
			if !isValidComponentMatcher(componentLen, wildcardLen) {
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
	// Final component
	return isValidComponentMatcher(componentLen, wildcardLen)
}

func isValidComponentMatcher(componentLen, wildcardLen int) bool {
	if wildcardLen > 2 {
		// No more than two wildcards per component
		return false
	}
	if wildcardLen > 0 && wildcardLen != componentLen {
		// Wildcard can't be mixed with other characters in the same component
		return false
	}
	// Component must not be empty
	return componentLen > 0
}

func isValidPatternRune(c rune) bool {
	return isValidRune(c) || c == '*'
}

// PatternNew can be used to match secret identifiers.
// Valid patterns must follow the same validation rules as secret identifiers, with the exception
// that '*' can be used to match a single component, and '**' can be used to match zero or more components.
type PatternNew interface {
	// Match the [PatternNew] against an [IDNew]
	Match(id IDNew) bool
	// String formats the [Pattern] as a string
	String() string

	json.Marshaler
	json.Unmarshaler
}

type pattern struct {
	value string
}

func (p *pattern) Match(id IDNew) bool {
	pathParts := split(id.String())
	patternParts := split(p.value)

	return match(patternParts, pathParts)
}

func (p *pattern) String() string {
	return p.value
}

func (p *pattern) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.value)
}

func (p *pattern) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if !validPattern(s) {
		return ErrInvalidPattern
	}
	p.value = s
	return nil
}

var _ PatternNew = &pattern{}

// ParsePatternNew parses a string into a [PatternNew]
// Rules:
// - Components separated by '/'
// - Each component is non-empty
// - Only characters A-Z, a-z, 0-9, '.', '-', '_' or '*'
// - No leading, trailing, or double slashes
// - Asterisks rules:
//   - '*' cannot be mixed with other characters in the same component
//   - there can be no more than two '*' per component
func ParsePatternNew(s string) (PatternNew, error) {
	if !validPattern(s) {
		return nil, ErrInvalidPattern
	}
	return &pattern{
		value: s,
	}, nil
}

// MustParsePatternNew parses a string into a [PatternNew] like with [ParsePatternNew],
// however, it panics when a validation error occurs.
func MustParsePatternNew(s string) PatternNew {
	if !validPattern(s) {
		panic(ErrInvalidPattern)
	}
	return &pattern{
		value: s,
	}
}
