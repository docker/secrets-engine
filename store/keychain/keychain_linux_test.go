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

//go:build linux

package keychain

import (
	"testing"

	dbus "github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveDefaultCollection(t *testing.T) {
	const customCollection = dbus.ObjectPath("/org/freedesktop/secrets/collection/custom")

	tests := []struct {
		name        string
		collections []dbus.ObjectPath
		aliasPath   dbus.ObjectPath
		want        dbus.ObjectPath
		wantErr     error
	}{
		{
			name:        "prefers login collection when present",
			collections: []dbus.ObjectPath{customCollection, loginKeychainObjectPath},
			// even if the alias points elsewhere, login wins
			aliasPath: customCollection,
			want:      loginKeychainObjectPath,
		},
		{
			name:        "falls back to default alias when login is absent",
			collections: []dbus.ObjectPath{customCollection},
			aliasPath:   customCollection,
			want:        customCollection,
		},
		{
			name: "rejects null path from unassigned default alias",
			// headless host: no login collection, no default alias set, so
			// ReadAlias returns the null object path "/"
			collections: []dbus.ObjectPath{},
			aliasPath:   nullObjectPath,
			wantErr:     ErrNoDefaultCollection,
		},
		{
			name:        "rejects syntactically invalid alias path",
			collections: []dbus.ObjectPath{},
			aliasPath:   dbus.ObjectPath(""),
			// distinct from the null-path case; see resolveDefaultCollection
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDefaultCollection(tt.collections, tt.aliasPath)

			switch {
			case tt.wantErr != nil:
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, got)
			case tt.want == "":
				// invalid path case: an error is expected, value is empty
				require.Error(t, err)
				assert.Empty(t, got)
			default:
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
