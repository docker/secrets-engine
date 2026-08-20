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

package realms

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/x/secrets"
)

func TestAccessorsReturnCopies(t *testing.T) {
	accessors := map[string]func() []secrets.Pattern{
		"All":              All,
		"AllAuth":          AllAuth,
		"AllMCP":           AllMCP,
		"AllSandbox":       AllSandbox,
		"AllSecretsEngine": AllSecretsEngine,
	}
	for name, accessor := range accessors {
		t.Run(name, func(t *testing.T) {
			original := accessor()[0]
			mutated := accessor()
			mutated[0] = secrets.MustParsePattern("mutated/**")
			assert.Equal(t, original, accessor()[0])
		})
	}
}

// TestRealmsListedOnce ensures no realm is listed in more than one group; the
// canonical set is the concatenation of the groups, so a duplicate would show
// up in All.
func TestRealmsListedOnce(t *testing.T) {
	seen := make(map[string]bool)
	for _, r := range All() {
		assert.False(t, seen[r.String()], "realm %s listed more than once", r)
		seen[r.String()] = true
	}
}

// TestEveryExportedRealmIsListed guards the canonical set against drift:
// every exported package-level var must be listed in one of the group sets so
// it lands in All. It counts the exported top-level vars in the package
// sources and compares against the canonical set.
func TestEveryExportedRealmIsListed(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	var exported int
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.VAR {
				continue
			}
			for _, spec := range genDecl.Specs {
				for _, ident := range spec.(*ast.ValueSpec).Names {
					if ident.IsExported() {
						exported++
					}
				}
			}
		}
	}
	assert.Equal(t, exported, len(All()),
		"every exported realm var must be listed in a group set so All() includes it")
}
