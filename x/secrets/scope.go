package secrets

import "strings"

type Scope interface {
	Forward(pattern Pattern) (Pattern, bool)
}

//type ReversibleScope interface {
//	Scope
//	Reverse(id ID) ID
//}

type dscope struct {
	pattern Pattern
}

func (d dscope) Forward(pattern Pattern) (Pattern, bool) {
	components, _ := forward(split(d.pattern.String()), split(pattern.String()))
	fwd, err := ParsePattern(strings.Join(components, "/"))
	if err != nil {
		return nil, false
	}
	return fwd, true
}

func NewDynamicScope(s string) (Scope, error) {
	p, err := ParsePattern(s)
	if err != nil {
		return nil, err
	}
	return dscope{
		pattern: p,
	}, nil
}

//nolint:gocyclo
func forward(pattern, path []string) ([]string, bool) {
	var fwd []string
	pi, si := 0, 0

	for pi < len(pattern) && si < len(path) {
		switch pattern[pi] {
		case "**":
			if pi+1 == len(pattern) {
				return append(fwd, path[si:]...), true
			}

			if path[si] == "**" {
				offset := pi
				// replace ** in path with the {*|**} mask coming from pattern
				// eg ** could get replaced with **/*, **/*/**, **/*/**/*, etc
				for offset+1 < len(pattern) && (pattern[offset+1] == "**" || pattern[offset+1] == "*") {
					offset++
				}
				next := pi + 1
				if offset > pi {
					next = offset
				}

				if fwdSub, ok := forward(pattern[next:], path[si:]); ok {
					return append(append(fwd, pattern[pi:offset]...), fwdSub...), true
				}

				// -> both act as **
				if fwdSub, ok := forward(pattern[pi+1:], path[si+1:]); ok {
					return append(append(fwd, "**"), fwdSub...), true
				}

				return nil, false
			}

			for skip := 0; si+skip <= len(path); skip++ {
				if fwdSub, ok := forward(pattern[pi+1:], path[si+skip:]); ok {
					return append(append(fwd, path[si:si+skip]...), fwdSub...), true
				}
			}
			return nil, false
		case "*":
			if path[si] == "**" {
				if si+1 == len(path) {
					fwd = append(fwd, "*")
					pi++
					if pi == len(pattern) {
						si++
					}
				} else {
					if fwdSub, ok := forward(pattern[pi:], append([]string{"*"}, path[si+1:]...)); ok {
						return append(fwd, fwdSub...), true
					}
					if fwdSub, ok := forward(pattern[pi:], path[si+1:]); ok {
						return append(fwd, fwdSub...), true
					}
					return nil, false
				}
			} else {
				fwd = append(fwd, path[si])
				pi++
				si++
			}
		default:
			switch path[si] {
			case "*", pattern[pi]:
				pi++
				si++
			case "**":
				if pi+1 == len(pattern) {
					if si+1 != len(path) {
						return nil, false
					}
					return append(fwd, path[si]), true
				}
				if si+1 == len(path) {
					pi++
				} else {
					if fwdSub, ok := forward(pattern[pi+1:], path[si:]); ok {
						return append(fwd, fwdSub...), true
					}
					if fwdSub, ok := forward(pattern[pi:], path[si+1:]); ok {
						return append(fwd, fwdSub...), true
					}
					if fwdSub, ok := forward(pattern[pi:], append([]string{"*"}, path[si+1:]...)); ok {
						return append(fwd, fwdSub...), true
					}
					return nil, false
				}

			default:
				if pattern[pi] != path[si] {
					return nil, false
				}
			}

		}
	}

	if pi < len(pattern) || si < len(path) {
		return nil, false
	}

	return fwd, true
}
