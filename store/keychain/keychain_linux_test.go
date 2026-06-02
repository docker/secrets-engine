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

	"github.com/docker/secrets-engine/store"
	kc "github.com/docker/secrets-engine/store/keychain/internal/go-keychain/secretservice"
)

// fakeService is a pure in-memory [secretService]. It never talks to a real
// secret service over dbus, so tests that drive the store through it are
// deterministic and need no keyring on the host.
//
// It records how many connections were opened and closed so a test can assert
// the store balances every open with a Close.
type fakeService struct {
	// items is returned verbatim by SearchCollection; leave empty to drive the
	// "credential not found" path.
	items []dbus.ObjectPath

	opened int
	closed int
}

func (f *fakeService) Collections() ([]dbus.ObjectPath, error) {
	return []dbus.ObjectPath{loginKeychainObjectPath}, nil
}
func (f *fakeService) ReadAlias(string) (dbus.ObjectPath, error) { return loginKeychainObjectPath, nil }
func (f *fakeService) IsLocked(dbus.ObjectPath) (bool, error)    { return false, nil }
func (f *fakeService) OpenSession(kc.AuthenticationMode) (*kc.Session, error) {
	return &kc.Session{}, nil
}
func (f *fakeService) CloseSession(*kc.Session)       {}
func (f *fakeService) Unlock([]dbus.ObjectPath) error { return nil }
func (f *fakeService) SearchCollection(dbus.ObjectPath, kc.Attributes) ([]dbus.ObjectPath, error) {
	return f.items, nil
}
func (f *fakeService) CreateItem(dbus.ObjectPath, map[string]dbus.Variant, kc.Secret, kc.ReplaceBehavior) (dbus.ObjectPath, error) {
	return "", nil
}
func (f *fakeService) DeleteItem(dbus.ObjectPath) error                      { return nil }
func (f *fakeService) GetAttributes(dbus.ObjectPath) (kc.Attributes, error)  { return nil, nil }
func (f *fakeService) GetSecret(dbus.ObjectPath, kc.Session) ([]byte, error) { return nil, nil }
func (f *fakeService) Close() error {
	f.closed++
	return nil
}

// withFakeService swaps the package newService seam for one that hands out the
// given fake (counting each open) and restores the original on cleanup.
func withFakeService(t *testing.T, fake *fakeService) {
	t.Helper()
	orig := newService
	t.Cleanup(func() { newService = orig })
	newService = func() (secretService, error) {
		fake.opened++
		return fake, nil
	}
}

// TestKeychainGetNotFound exercises the full Get path against the fake — open,
// resolve collection, search — and asserts an empty search maps to
// ErrCredentialNotFound, all without a live keyring.
func TestKeychainGetNotFound(t *testing.T) {
	fake := &fakeService{} // no items -> not found
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	_, err := ks.Get(t.Context(), store.MustParseID("com.test.test/test/missing"))
	assert.ErrorIs(t, err, store.ErrCredentialNotFound)
}

// TestKeychainClosesEveryConnection is a deterministic regression test for the
// D-Bus connection leak: each keychain operation dials a fresh connection via
// newService and must Close it. Driving the store through a fake lets us assert
// the contract directly — every opened connection is closed — instead of
// counting host file descriptors.
func TestKeychainClosesEveryConnection(t *testing.T) {
	fake := &fakeService{} // no items -> Get returns ErrCredentialNotFound
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	missing := store.MustParseID("com.test.test/test/missing")

	const iterations = 30
	for range iterations {
		_, err := ks.Get(t.Context(), missing)
		require.ErrorIs(t, err, store.ErrCredentialNotFound)
	}

	require.Equal(t, iterations, fake.opened)
	assert.Equal(t, fake.opened, fake.closed, "every opened connection must be closed")
}

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
