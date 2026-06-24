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
	"context"
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

	// recorded write operations, for assertions in the Save tests. Not
	// concurrency-safe: the tests that read them drive a single sequential
	// operation through the fake.
	createCalls    int
	setSecretCalls int
	deleteCalls    int
	setSecretItems []dbus.ObjectPath
	deletedItems   []dbus.ObjectPath

	// {createItem,setSecret,deleteItem}LockedErrs is how many leading calls of
	// each kind fail with the secret service "collection is locked" D-Bus error
	// before one succeeds, simulating a collection that relocks underneath the
	// store (see withRelockRetry). The error is wrapped exactly as the real
	// service wraps it, so the tests exercise the errors.As-through-wrap path
	// isLockedDBusError depends on. unlockCalls counts the re-unlocks the retry
	// issues; unlockErr, when set, makes Unlock fail (e.g. a dismissed prompt).
	createItemLockedErrs int
	setSecretLockedErrs  int
	deleteItemLockedErrs int
	unlockCalls          int
	unlockErr            error

	opened atomic.Int64
	closed atomic.Int64
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
	// plain mode so Session.NewSecret works without a negotiated AES key, which
	// lets the Save path run end-to-end against the fake.
	return &kc.Session{Mode: kc.AuthenticationInsecurePlain}, nil
}
func (f *fakeService) CloseSession(*kc.Session) {}
func (f *fakeService) Unlock([]dbus.ObjectPath) error {
	f.unlockCalls++
	return f.unlockErr
}

func (f *fakeService) SearchCollection(dbus.ObjectPath, kc.Attributes) ([]dbus.ObjectPath, error) {
	return f.items, nil
}

func (f *fakeService) CreateItem(dbus.ObjectPath, map[string]dbus.Variant, kc.Secret, kc.ReplaceBehavior) (dbus.ObjectPath, error) {
	f.createCalls++
	if f.createCalls <= f.createItemLockedErrs {
		return "", lockedErr("create item")
	}
	return "/created", nil
}

func (f *fakeService) DeleteItem(item dbus.ObjectPath) error {
	f.deleteCalls++
	if f.deleteCalls <= f.deleteItemLockedErrs {
		return lockedErr("delete item")
	}
	f.deletedItems = append(f.deletedItems, item)
	return nil
}
func (f *fakeService) GetAttributes(dbus.ObjectPath) (kc.Attributes, error)  { return nil, nil }
func (f *fakeService) GetSecret(dbus.ObjectPath, kc.Session) ([]byte, error) { return nil, nil }
func (f *fakeService) SetItemSecret(item dbus.ObjectPath, _ kc.Secret) error {
	f.setSecretCalls++
	if f.setSecretCalls <= f.setSecretLockedErrs {
		return lockedErr("set item secret")
	}
	f.setSecretItems = append(f.setSecretItems, item)
	return nil
}
func (f *fakeService) SetItemAttributes(dbus.ObjectPath, kc.Attributes) error { return nil }
func (f *fakeService) SetItemLabel(dbus.ObjectPath, string) error             { return nil }
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
// run without real delays, restoring it on cleanup. It mutates the package-level
// sleepFn var, so tests using it must not run in parallel.
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

// TestKeychainSaveCreatesWhenAbsent asserts Save mints a new item only when the
// identity has no existing item, and performs no in-place update or cleanup.
func TestKeychainSaveCreatesWhenAbsent(t *testing.T) {
	fake := &fakeService{} // no items -> create path
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	id := store.MustParseID("com.test.test/test/new-user")
	creds := &mocks.MockCredential{Username: "alice", Password: "alice-password"}

	require.NoError(t, ks.Save(t.Context(), id, creds))

	assert.Equal(t, 1, fake.createCalls, "must CreateItem when no existing item")
	assert.Empty(t, fake.setSecretItems, "no in-place update when creating")
	assert.Empty(t, fake.deletedItems, "nothing to collapse")
}

// TestKeychainSaveCollapsesDuplicatesInPlace is the issue #446 regression test:
// when several items already share one stable identity (the accumulated
// duplicates), Save must update the first match in place — never minting a new
// item — and drain the remaining duplicates, leaving exactly one.
func TestKeychainSaveCollapsesDuplicatesInPlace(t *testing.T) {
	fake := &fakeService{
		items: []dbus.ObjectPath{"/item/a", "/item/b", "/item/c"},
	}
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	id := store.MustParseID("com.test.test/test/bob")
	creds := &mocks.MockCredential{Username: "bob", Password: "bob-password"}

	require.NoError(t, ks.Save(t.Context(), id, creds))

	assert.Zero(t, fake.createCalls, "must not CreateItem when an item already exists")
	assert.Equal(t, []dbus.ObjectPath{"/item/a"}, fake.setSecretItems,
		"secret must be rewritten on the first match in place")
	assert.ElementsMatch(t, []dbus.ObjectPath{"/item/b", "/item/c"}, fake.deletedItems,
		"the remaining duplicates must be collapsed, leaving only the first match")
}

// TestKeychainSaveRetriesWhenCreateRelocks covers the create path: gnome-keyring
// can relock the collection between the unlock and the CreateItem, so a fresh
// Save must react to the locked error by unlocking and retrying rather than
// failing.
func TestKeychainSaveRetriesWhenCreateRelocks(t *testing.T) {
	stubRelockSleep(t)
	fake := &fakeService{} // no items -> create path
	fake.createItemLockedErrs = 2
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	require.NoError(t, ks.Save(t.Context(), store.MustParseID("com.test.test/test/bob"),
		&mocks.MockCredential{Username: "bob", Password: "bob-password"}))

	assert.Equal(t, 3, fake.createCalls, "two locked failures then one success")
	assert.Equal(t, 2, fake.unlockCalls, "exactly one Unlock per relock retry")
}

// TestKeychainSaveRetriesWhenSetSecretRelocks covers the in-place update path:
// the SetItemSecret that rewrites the surviving item must survive a relock.
func TestKeychainSaveRetriesWhenSetSecretRelocks(t *testing.T) {
	stubRelockSleep(t)
	fake := &fakeService{items: []dbus.ObjectPath{"/item/a"}}
	fake.setSecretLockedErrs = 2
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	require.NoError(t, ks.Save(t.Context(), store.MustParseID("com.test.test/test/bob"),
		&mocks.MockCredential{Username: "bob", Password: "bob-password"}))

	assert.Equal(t, []dbus.ObjectPath{"/item/a"}, fake.setSecretItems,
		"the secret must be written in place once the relock clears")
	assert.Equal(t, 2, fake.unlockCalls, "exactly one Unlock per relock retry")
}

// TestKeychainSaveCollapseRetriesWhenDeleteRelocks is the unit-level counterpart
// of the real-keyring backlog test: collapsing a duplicate must drain it even if
// the collection relocks mid-delete. The collapse delete is best-effort, but a
// silently swallowed locked error would leave the duplicate behind — the exact
// #446 symptom — so it is still relock-aware.
func TestKeychainSaveCollapseRetriesWhenDeleteRelocks(t *testing.T) {
	stubRelockSleep(t)
	fake := &fakeService{items: []dbus.ObjectPath{"/item/a", "/item/b"}}
	fake.deleteItemLockedErrs = 2
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	require.NoError(t, ks.Save(t.Context(), store.MustParseID("com.test.test/test/bob"),
		&mocks.MockCredential{Username: "bob", Password: "bob-password"}))

	assert.Equal(t, []dbus.ObjectPath{"/item/b"}, fake.deletedItems,
		"the duplicate must be collapsed once the relock clears")
	assert.Equal(t, 3, fake.deleteCalls, "two locked failures then one success")
	assert.Equal(t, 2, fake.unlockCalls, "exactly one Unlock per relock retry")
}

// TestKeychainSaveStopsRetryingAfterMaxRelocks asserts the retry is bounded: a
// persistently locked collection surfaces the locked error to the caller instead
// of looping forever.
func TestKeychainSaveStopsRetryingAfterMaxRelocks(t *testing.T) {
	stubRelockSleep(t)
	fake := &fakeService{}              // no items -> create path
	fake.createItemLockedErrs = 1 << 30 // never recovers
	withFakeService(t, fake)

	ks := setupKeychain(t, nil)
	err := ks.Save(t.Context(), store.MustParseID("com.test.test/test/bob"),
		&mocks.MockCredential{Username: "bob", Password: "bob-password"})
	require.Error(t, err)
	assert.True(t, isLockedDBusError(err), "the persistent locked error must reach the caller")
	assert.Equal(t, maxRelockRetries+1, fake.createCalls, "initial attempt plus the bounded retries")
}

// The real-keychain dedup tests use their own service group/name so their items
// are namespace-isolated from TestKeychain (which shares com.test.test/test).
// GetAllMetadata/Filter search by {service:group, service:name}, so a leaked
// dedup item can never show up in — and break — the shared suite.
const (
	dedupServiceGroup = "com.test.dedup"
	dedupServiceName  = "dedup"
)

// ensureUnlocked unlocks the collection and waits until the daemon actually
// reports it unlocked. The freedesktop Unlock call can return before the
// collection is fully unlocked, so a CreateItem/DeleteItem issued immediately
// after can still fail with "locked collection" — polling IsLocked closes that
// race. (The store's own Save/Get/Delete avoid it only because the collection
// stays unlocked once any earlier operation has unlocked it.)
func ensureUnlocked(t *testing.T, svc *kc.SecretService, collection dbus.ObjectPath) {
	t.Helper()
	require.NoError(t, svc.Unlock([]dbus.ObjectPath{collection}))
	require.Eventually(t, func() bool {
		locked, err := svc.IsLocked(collection)
		return err == nil && !locked
	}, 5*time.Second, 100*time.Millisecond, "collection did not unlock")
}

// searchRealItems queries a live Secret Service for every item sharing id's
// stable identity triple {service:group, service:name, id}. The store API keys
// results by ID and so would collapse duplicates into one logical entry —
// counting the physical items requires going under it, straight to the daemon.
//
// It opens its own short-lived connection (mirroring how the store dials a fresh
// connection per operation) so it observes exactly what an independent client
// would see. Object paths it returns stay valid after the connection closes.
//
// It returns its error rather than failing the test so it is safe to call from a
// [require.Eventually] condition, which runs on a separate goroutine where the
// require.* helpers must not be used.
func searchRealItems(serviceGroup, serviceName string, id store.ID) ([]dbus.ObjectPath, error) {
	svc, err := kc.NewService()
	if err != nil {
		return nil, err
	}
	defer func() { _ = svc.Close() }()

	collection, err := getDefaultCollection(svc)
	if err != nil {
		return nil, err
	}

	attrs := map[string]string{}
	safelySetMetadata(serviceGroup, serviceName, attrs)
	safelySetID(id, attrs)

	return svc.SearchCollection(collection, attrs)
}

// findRealItems is the test-goroutine wrapper around [searchRealItems] that fails
// the test on error.
func findRealItems(t *testing.T, serviceGroup, serviceName string, id store.ID) []dbus.ObjectPath {
	t.Helper()
	items, err := searchRealItems(serviceGroup, serviceName, id)
	require.NoError(t, err)
	return items
}

// requireItemCount polls the live Secret Service until exactly want items remain
// for id, failing after a short timeout. Polling absorbs any lag between the
// store deleting duplicates and an independent connection observing it; on
// timeout EventuallyWithT reports the last observed count (and any search
// error), so a genuine failure to converge is still caught and diagnosable.
func requireItemCount(t *testing.T, serviceGroup, serviceName string, id store.ID, want int, msg string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		items, err := searchRealItems(serviceGroup, serviceName, id)
		assert.NoError(c, err)
		assert.Len(c, items, want, msg)
	}, 10*time.Second, 200*time.Millisecond)
}

// seedRealDuplicates creates n separate Secret Service items that all share id's
// stable identity triple but carry a distinct volatile attribute each — exactly
// how issue #446 accumulates duplicates: the daemon's replace match fails on the
// differing volatile attributes, so every save mints a fresh item.
func seedRealDuplicates(t *testing.T, serviceGroup, serviceName string, id store.ID, n int) {
	t.Helper()
	svc, err := kc.NewService()
	require.NoError(t, err)
	defer func() { _ = svc.Close() }()

	session, err := svc.OpenSession(kc.AuthenticationDHAES)
	require.NoError(t, err)
	defer svc.CloseSession(session)

	collection, err := getDefaultCollection(svc)
	require.NoError(t, err)

	// Talking to the daemon directly skips the unlock the store does internally,
	// and gnome-keyring reports even the passwordless 'login' collection as
	// locked until then.
	ensureUnlocked(t, svc, collection)

	label := serviceGroup + ":" + serviceName + ":" + id.String()
	for i := range n {
		sessSecret, err := session.NewSecret(fmt.Appendf(nil, "seed-user:seed-pass-%d", i))
		require.NoError(t, err)

		attrs := map[string]string{
			// volatile: distinct per item, so each CreateItem adds a new one
			// rather than replacing — the duplicate-accumulation pattern.
			"nonce": fmt.Sprintf("seed-%d", i),
		}
		safelySetMetadata(serviceGroup, serviceName, attrs)
		safelySetID(id, attrs)

		// Seed directly against the daemon, but stay relock-aware: a prior op's
		// closing connection can relock the collection between the unlock above
		// and this create (see withRelockRetry), which would otherwise fail the
		// seed with "Cannot create an item in a locked collection".
		err = withRelockRetry(svc, collection, func() error {
			_, createErr := svc.CreateItem(collection, kc.NewSecretProperties(label, attrs), sessSecret, kc.ReplaceBehaviorDoNotReplace)
			return createErr
		})
		require.NoError(t, err)
	}
}

// purgeRealItems removes every item for id, draining any leftover duplicates so
// the test cannot leak state. It unlocks the collection first (DeleteItem fails
// on a locked collection) and deletes all matches, asserting success so a silent
// cleanup failure surfaces as a leak rather than corrupting a later test.
func purgeRealItems(t *testing.T, serviceGroup, serviceName string, id store.ID) {
	t.Helper()
	svc, err := kc.NewService()
	require.NoError(t, err)
	defer func() { _ = svc.Close() }()

	collection, err := getDefaultCollection(svc)
	require.NoError(t, err)
	ensureUnlocked(t, svc, collection)

	attrs := map[string]string{}
	safelySetMetadata(serviceGroup, serviceName, attrs)
	safelySetID(id, attrs)
	items, err := svc.SearchCollection(collection, attrs)
	require.NoError(t, err)
	for _, item := range items {
		require.NoError(t, withRelockRetry(svc, collection, func() error {
			return svc.DeleteItem(item)
		}))
	}
}

// TestKeychainCollapsesExistingDuplicates is the issue #446 backlog test against
// a real Secret Service: given several duplicate items already stored under one
// identity, a single Save must update one item in place and delete the rest,
// leaving exactly one item holding the latest secret.
func TestKeychainCollapsesExistingDuplicates(t *testing.T) {
	id := store.MustParseID(dedupServiceGroup + "/" + dedupServiceName + "/backlog")
	t.Cleanup(func() { purgeRealItems(t, dedupServiceGroup, dedupServiceName, id) })

	// Pre-existing backlog: three duplicate items for one identity.
	seedRealDuplicates(t, dedupServiceGroup, dedupServiceName, id, 3)
	require.Len(t, findRealItems(t, dedupServiceGroup, dedupServiceName, id), 3, "precondition: three duplicates seeded")

	ks, err := New(dedupServiceGroup, dedupServiceName, func(_ context.Context, _ store.ID) store.Secret {
		return &mocks.MockCredential{}
	})
	require.NoError(t, err)

	require.NoError(t, ks.Save(t.Context(), id, &mocks.MockCredential{
		Username: "backlog-user",
		Password: "final-password",
	}))

	requireItemCount(t, dedupServiceGroup, dedupServiceName, id, 1,
		"a single Save must collapse the duplicate backlog to one item")

	got, err := ks.Get(t.Context(), id)
	require.NoError(t, err)
	assert.Equal(t, "final-password", got.(*mocks.MockCredential).Password,
		"the surviving item must hold the latest secret")
}

// TestKeychainSaveDoesNotAccumulate is the forward-looking issue #446 test
// against a real Secret Service: saving the same identity repeatedly with
// metadata that changes on every save (mimicking volatile JWT claims) must keep
// exactly one item, never minting duplicates.
func TestKeychainSaveDoesNotAccumulate(t *testing.T) {
	id := store.MustParseID(dedupServiceGroup + "/" + dedupServiceName + "/no-accumulate")
	t.Cleanup(func() { purgeRealItems(t, dedupServiceGroup, dedupServiceName, id) })

	ks, err := New(dedupServiceGroup, dedupServiceName, func(_ context.Context, _ store.ID) store.Secret {
		return &mocks.MockCredential{}
	})
	require.NoError(t, err)

	const saves = 5
	for i := range saves {
		require.NoError(t, ks.Save(t.Context(), id, &mocks.MockCredential{
			Username: "no-accumulate-user",
			Password: fmt.Sprintf("password-%d", i),
			Attributes: map[string]string{
				"nonce": fmt.Sprintf("%d", i), // volatile: differs every save
			},
		}))
	}

	requireItemCount(t, dedupServiceGroup, dedupServiceName, id, 1,
		"saving with changing metadata must not accumulate duplicate items")

	got, err := ks.Get(t.Context(), id)
	require.NoError(t, err)
	actual := got.(*mocks.MockCredential)
	assert.Equal(t, fmt.Sprintf("password-%d", saves-1), actual.Password)
	assert.Equal(t, fmt.Sprintf("%d", saves-1), actual.Attributes["nonce"],
		"the surviving item's metadata must be refreshed in place")
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
