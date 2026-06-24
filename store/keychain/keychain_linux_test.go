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
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	dbus "github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/store"
	kc "github.com/docker/secrets-engine/store/keychain/internal/go-keychain/secretservice"
	"github.com/docker/secrets-engine/store/mocks"
)

// fakeService is a pure in-memory [secretService]. It never talks to a real
// secret service over dbus, so tests that drive the store through it are
// deterministic and need no keyring on the host.
//
// It records how many connections were opened and closed so a test can assert
// the store balances every open with a Close. The counters are atomic so the
// fake is safe to share across concurrent operations.
type fakeService struct {
	// items is returned verbatim by SearchCollection; leave empty to drive the
	// "credential not found" path.
	items []dbus.ObjectPath

	opened atomic.Int64
	closed atomic.Int64

	// {create,delete,getSecret}ItemLockedErrs is how many leading calls of each
	// kind fail with the secret service "collection is locked" D-Bus error
	// before one succeeds, simulating a collection that relocks underneath the
	// store (see withRelockRetry). The error is wrapped exactly as the real
	// service wraps it (fmt.Errorf("...: %w", dbus.Error{...})), so the tests
	// exercise the errors.As-through-wrap path isLockedDBusError depends on.
	createItemLockedErrs atomic.Int64
	createItemCalls      atomic.Int64
	deleteItemLockedErrs atomic.Int64
	deleteItemCalls      atomic.Int64
	getSecretLockedErrs  atomic.Int64
	getSecretCalls       atomic.Int64
	unlockCalls          atomic.Int64

	// unlockErr, when set, is returned by Unlock to simulate e.g. a dismissed
	// authentication prompt.
	unlockErr error
}

// lockedErr mirrors how the real SecretService wraps a locked-collection D-Bus
// error (see secretservice.go), so isLockedDBusError must unwrap to detect it.
func lockedErr(op string) error {
	return fmt.Errorf("failed to %s: %w", op, dbus.Error{Name: secretServiceIsLockedError})
}

func (f *fakeService) Collections() ([]dbus.ObjectPath, error) {
	return []dbus.ObjectPath{loginKeychainObjectPath}, nil
}
func (f *fakeService) ReadAlias(string) (dbus.ObjectPath, error) { return loginKeychainObjectPath, nil }
func (f *fakeService) IsLocked(dbus.ObjectPath) (bool, error)    { return false, nil }
func (f *fakeService) OpenSession(kc.AuthenticationMode) (*kc.Session, error) {
	// Plain mode lets Session.NewSecret wrap the value without negotiating an
	// AES key, so Save can drive CreateItem in tests without a live session.
	return &kc.Session{Mode: kc.AuthenticationInsecurePlain}, nil
}
func (f *fakeService) CloseSession(*kc.Session) {}
func (f *fakeService) Unlock([]dbus.ObjectPath) error {
	f.unlockCalls.Add(1)
	return f.unlockErr
}

func (f *fakeService) SearchCollection(dbus.ObjectPath, kc.Attributes) ([]dbus.ObjectPath, error) {
	return f.items, nil
}

func (f *fakeService) CreateItem(dbus.ObjectPath, map[string]dbus.Variant, kc.Secret, kc.ReplaceBehavior) (dbus.ObjectPath, error) {
	if f.createItemCalls.Add(1) <= f.createItemLockedErrs.Load() {
		return "", lockedErr("create item")
	}
	return "", nil
}

func (f *fakeService) DeleteItem(dbus.ObjectPath) error {
	if f.deleteItemCalls.Add(1) <= f.deleteItemLockedErrs.Load() {
		return lockedErr("delete item")
	}
	return nil
}
func (f *fakeService) GetAttributes(dbus.ObjectPath) (kc.Attributes, error) { return nil, nil }
func (f *fakeService) GetSecret(dbus.ObjectPath, kc.Session) ([]byte, error) {
	if f.getSecretCalls.Add(1) <= f.getSecretLockedErrs.Load() {
		return nil, lockedErr("get secret")
	}
	// A value MockCredential.Unmarshal can parse ("username:password"), so the
	// Get path completes once the simulated relock clears.
	return []byte("bob:bob-password"), nil
}

func (f *fakeService) Close() error {
	f.closed.Add(1)
	return nil
}

// withFakeService swaps the package newService seam for one that hands out the
// given fake (counting each open) and restores the original on cleanup.
func withFakeService(t *testing.T, fake *fakeService) {
	t.Helper()
	orig := newService
	t.Cleanup(func() { newService = orig })
	newService = func() (secretService, error) {
		fake.opened.Add(1)
		return fake, nil
	}
}

// stubRelockSleep replaces the relock backoff sleep with a no-op so retry tests
// run without real delays, restoring it on cleanup.
func stubRelockSleep(t *testing.T) {
	t.Helper()
	orig := sleepFn
	t.Cleanup(func() { sleepFn = orig })
	sleepFn = func(time.Duration) {}
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

	opened, closed := fake.opened.Load(), fake.closed.Load()
	require.Equal(t, int64(iterations), opened)
	assert.Equal(t, opened, closed, "every opened connection must be closed")
}

// TestSaveRetriesWhenCollectionRelocks is a regression test for the
// intermittent "Cannot create an item in a locked collection" flake. Because
// the store opens and closes a fresh D-Bus connection per operation, the secret
// service can relock the collection asynchronously, so a CreateItem can fail as
// locked even though the collection was observed unlocked moments earlier. Save
// must react to that locked error by unlocking and retrying rather than failing.
func TestSaveRetriesWhenCollectionRelocks(t *testing.T) {
	stubRelockSleep(t)
	fake := &fakeService{}
	fake.createItemLockedErrs.Store(2) // first two attempts hit a relocked collection
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	err := ks.Save(t.Context(), store.MustParseID("com.test.test/test/bob"), &mocks.MockCredential{
		Username: "bob",
		Password: "bob-password",
	})
	require.NoError(t, err)

	assert.Equal(t, int64(3), fake.createItemCalls.Load(), "two locked failures then one success")
	// The fake reports the collection as unlocked, so ensureUnlocked issues no
	// Unlock; every Unlock comes from withRelockRetry — exactly one per retry.
	assert.Equal(t, int64(2), fake.unlockCalls.Load(), "exactly one Unlock per relock retry")
}

// TestSaveStopsRetryingAfterMaxRelocks asserts the retry is bounded: a
// persistently locked collection surfaces the locked error instead of looping
// forever.
func TestSaveStopsRetryingAfterMaxRelocks(t *testing.T) {
	stubRelockSleep(t)
	fake := &fakeService{}
	fake.createItemLockedErrs.Store(1 << 30) // never recovers
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	err := ks.Save(t.Context(), store.MustParseID("com.test.test/test/bob"), &mocks.MockCredential{
		Username: "bob",
		Password: "bob-password",
	})
	require.Error(t, err)
	assert.True(t, isLockedDBusError(err), "the persistent locked error must be returned to the caller")
	assert.Equal(t, int64(maxRelockRetries+1), fake.createItemCalls.Load(), "initial attempt plus the bounded retries")
}

// TestSaveStopsRetryingWhenUnlockFails asserts the retry loop does not keep
// re-unlocking (and therefore re-prompting) once Unlock itself errors, e.g.
// when the user dismisses an authentication prompt. The Unlock error is
// surfaced after a single attempt.
func TestSaveStopsRetryingWhenUnlockFails(t *testing.T) {
	stubRelockSleep(t)
	dismissed := errors.New("prompt dismissed")
	fake := &fakeService{unlockErr: dismissed}
	fake.createItemLockedErrs.Store(1 << 30) // always locked, so a retry is attempted
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	err := ks.Save(t.Context(), store.MustParseID("com.test.test/test/bob"), &mocks.MockCredential{
		Username: "bob",
		Password: "bob-password",
	})
	require.ErrorIs(t, err, dismissed)
	assert.Equal(t, int64(1), fake.unlockCalls.Load(), "must not re-unlock (re-prompt) after the first Unlock fails")
	assert.Equal(t, int64(1), fake.createItemCalls.Load(), "only the initial attempt runs; the failed unlock aborts the retry")
}

// TestDeleteRetriesWhenCollectionRelocks covers the second mutating call site:
// Delete's DeleteItem is wrapped in withRelockRetry just like Save's CreateItem,
// so a relocked collection must be unlocked and retried rather than failing.
func TestDeleteRetriesWhenCollectionRelocks(t *testing.T) {
	stubRelockSleep(t)
	fake := &fakeService{items: []dbus.ObjectPath{"/org/freedesktop/secrets/collection/login/1"}}
	fake.deleteItemLockedErrs.Store(2)
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	err := ks.Delete(t.Context(), store.MustParseID("com.test.test/test/bob"))
	require.NoError(t, err)

	assert.Equal(t, int64(3), fake.deleteItemCalls.Load(), "two locked failures then one success")
	assert.Equal(t, int64(2), fake.unlockCalls.Load(), "exactly one Unlock per relock retry")
}

// TestGetRetriesWhenCollectionRelocks covers the read path: GetSecret can also
// hit org.freedesktop.Secret.Error.IsLocked if the collection relocks between
// ensureUnlocked and the read, so Get wraps it in withRelockRetry too.
func TestGetRetriesWhenCollectionRelocks(t *testing.T) {
	stubRelockSleep(t)
	fake := &fakeService{items: []dbus.ObjectPath{"/org/freedesktop/secrets/collection/login/1"}}
	fake.getSecretLockedErrs.Store(2)
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	secret, err := ks.Get(t.Context(), store.MustParseID("com.test.test/test/bob"))
	require.NoError(t, err)
	require.NotNil(t, secret)

	assert.Equal(t, int64(3), fake.getSecretCalls.Load(), "two locked failures then one success")
	assert.Equal(t, int64(2), fake.unlockCalls.Load(), "exactly one Unlock per relock retry")
}

// TestIsLockedDBusError pins the central contract the retry depends on:
// detection must work whether the locked error is a bare dbus.Error or wrapped
// (the real service wraps it as fmt.Errorf("...: %w", dbus.Error{...})), and
// must not match other errors.
func TestIsLockedDBusError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"bare locked dbus error", dbus.Error{Name: secretServiceIsLockedError}, true},
		{"wrapped locked dbus error", fmt.Errorf("failed to create item: %w", dbus.Error{Name: secretServiceIsLockedError}), true},
		{"doubly wrapped locked dbus error", fmt.Errorf("outer: %w", fmt.Errorf("failed to get secret: %w", dbus.Error{Name: secretServiceIsLockedError})), true},
		{"different dbus error name", dbus.Error{Name: "org.freedesktop.DBus.Error.Failed"}, false},
		{"plain error", errors.New("boom"), false},
		{"nil error", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isLockedDBusError(tt.err))
		})
	}
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
