package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
)

var ErrInvalidPattern = errors.New("invalid pattern")

// Pattern can be used to match secret identifiers.
// Valid patterns must follow the same validation rules as secret identifiers, with the exception
// that '*' can be used to match a single component, and '**' can be used to match zero or more components.
type Pattern interface {
	// Match the [Pattern] against an [ID]
	Match(id ID) bool
	// String formats the [Pattern] as a string
	String() string

	json.Unmarshaler
	json.Marshaler
}

type pattern struct {
	value string
}

// ParsePattern parses a string into a [Pattern]
func ParsePattern(s string) (Pattern, error) {
	if !validPattern(s) {
		return nil, ErrInvalidPattern
	}
	return &pattern{
		value: s,
	}, nil
}

// MustParsePattern parses a string into a [Pattern] like with [ParsePattern],
// however, it panics when a validation error occurs.
func MustParsePattern(s string) Pattern {
	if !validPattern(s) {
		panic(ErrInvalidPattern)
	}
	return &pattern{
		value: s,
	}
}

func (p *pattern) Match(id ID) bool {
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
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&s); err != nil {
		return err
	}

	if dec.More() {
		return errors.New("secrets.Pattern does not support more than one JSON object")
	}

	if !validPattern(s) {
		return ErrInvalidPattern
	}
	p.value = s
	return nil
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
