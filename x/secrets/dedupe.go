// Copyright 2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secrets

import "strings"

type tokenKind uint8

const (
	tokenLit tokenKind = iota
	tokenStar
	tokenGap
)

type token struct {
	kind tokenKind
	lit  string
}

// canonicalize tokenizes a pattern such that two patterns match the same
// identifiers iff their tokens are equal: wildcard runs collapse into '*'s
// followed by one '**', and a pure-'**' pattern becomes "*/**" since
// identifiers are never empty.
func canonicalize(s string) []token {
	parts := split(s)
	toks := make([]token, 0, len(parts))
	stars, gap := 0, false
	flush := func() {
		for range stars {
			toks = append(toks, token{kind: tokenStar})
		}
		if gap {
			toks = append(toks, token{kind: tokenGap})
		}
		stars, gap = 0, false
	}
	for _, part := range parts {
		switch part {
		case "*":
			stars++
		case "**":
			gap = true
		default:
			flush()
			toks = append(toks, token{kind: tokenLit, lit: part})
		}
	}
	flush()
	if len(toks) == 1 && toks[0].kind == tokenGap {
		toks = []token{{kind: tokenStar}, {kind: tokenGap}}
	}
	return toks
}

func canonicalKey(toks []token) string {
	var sb strings.Builder
	for i, t := range toks {
		if i > 0 {
			sb.WriteByte('/')
		}
		switch t.kind {
		case tokenStar:
			sb.WriteByte('*')
		case tokenGap:
			sb.WriteString("**")
		case tokenLit:
			sb.WriteString(t.lit)
		}
	}
	return sb.String()
}

// includes reports whether p matches every identifier q matches, for
// canonical tokens. The component alphabet is unbounded, so a literal in p
// never covers a '*' or '**' in q.
func includes(p, q []token) bool {
	np, nq := len(p), len(q)
	// dp[j] == "p[i:] includes q[j:]"; row i needs only row i+1 (prev).
	prev := make([]bool, nq+1)
	cur := make([]bool, nq+1)
	prev[nq] = true
	for i := np - 1; i >= 0; i-- {
		cur[nq] = p[i].kind == tokenGap && prev[nq]
		for j := nq - 1; j >= 0; j-- {
			switch {
			case p[i].kind == tokenGap:
				cur[j] = prev[j] || cur[j+1]
			case q[j].kind == tokenGap:
				// q's gap may be empty or start with an unknown component.
				cur[j] = p[i].kind == tokenStar && cur[j+1] && prev[j]
			case p[i].kind == tokenStar:
				cur[j] = prev[j+1]
			default:
				cur[j] = q[j].kind == tokenLit && p[i].lit == q[j].lit && prev[j+1]
			}
		}
		prev, cur = cur, prev
	}
	return prev[0]
}

// Dedupe removes every pattern whose matches are all covered by another
// entry, keeping the first of equivalent spellings and preserving input
// order. Containment is over identifiers (at least one component) and is
// stricter than [Pattern.Includes]. Worst case O(n²·L²).
func Dedupe(patterns []Pattern) []Pattern {
	entries := make([]dedupeEntry, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, p := range patterns {
		toks := canonicalize(p.String())
		key := canonicalKey(toks)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, newDedupeEntry(p, toks))
	}

	result := make([]Pattern, 0, len(entries))
	for i := range entries {
		redundant := false
		for j := range entries {
			if i == j || !subsumes(&entries[j], &entries[i]) {
				continue
			}
			// Keep the earlier entry on (impossible) mutual inclusion.
			if j < i || !includes(entries[i].toks, entries[j].toks) {
				redundant = true
				break
			}
		}
		if !redundant {
			result = append(result, entries[i].original)
		}
	}
	return result
}

type dedupeEntry struct {
	original Pattern
	toks     []token
	minLen   int // non-gap token count: shortest matched identifier
	hasWild  bool
	hasGaps  bool
	firstLit string // literal anchors; "" when that end is a wildcard
	lastLit  string
}

func newDedupeEntry(p Pattern, toks []token) dedupeEntry {
	e := dedupeEntry{original: p, toks: toks}
	for _, t := range toks {
		if t.kind != tokenLit {
			e.hasWild = true
		}
		if t.kind == tokenGap {
			e.hasGaps = true
		} else {
			e.minLen++
		}
	}
	if len(toks) > 0 {
		e.firstLit = toks[0].lit
		e.lastLit = toks[len(toks)-1].lit
	}
	return e
}

// subsumes reports whether other matches every identifier e matches, with
// cheap filters before the containment check.
func subsumes(other, e *dedupeEntry) bool {
	// An all-literal pattern only includes itself, and equivalent entries
	// are already removed.
	if !other.hasWild {
		return false
	}
	if other.minLen > e.minLen {
		return false
	}
	// Gap-free other has no slack: e must be gap-free with equal length.
	if !other.hasGaps && (e.hasGaps || other.minLen != e.minLen) {
		return false
	}
	if other.firstLit != "" && other.firstLit != e.firstLit {
		return false
	}
	if other.lastLit != "" && other.lastLit != e.lastLit {
		return false
	}
	return includes(other.toks, e.toks)
}
