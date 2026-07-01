// Copyright 2025-2026 Docker, Inc.
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

// The keychain package for Linux uses the org.freedesktop.secret service API
// over dbus.
// For more information on the Secret Service API, see https://specifications.freedesktop.org/secret-service-spec/latest/index.html.
package keychain

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	dbus "github.com/godbus/dbus/v5"

	kc "github.com/docker/secrets-engine/store/keychain/internal/go-keychain/secretservice"

	"github.com/docker/secrets-engine/store"
)

const (
	// the default collection in most X11 sessions would be 'login'
	// it is created by default through PAM, see https://wiki.gnome.org/Projects/GnomeKeyring/Pam.
	//
	// NOTE: do not use this directly, always call [getDefaultCollection]
	loginKeychainObjectPath = dbus.ObjectPath("/org/freedesktop/secrets/collection/login")

	// the null/root object path returned by the secret service when an alias is
	// not assigned to any collection. It is syntactically valid (so
	// [dbus.ObjectPath.IsValid] returns true) but does not point at a real
	// collection, so it must be rejected explicitly.
	//
	// https://specifications.freedesktop.org/secret-service-spec/latest/org.freedesktop.Secret.Service.html#org.freedesktop.Secret.Service.ReadAlias
	nullObjectPath = dbus.ObjectPath("/")
)

// secretService is the subset of [kc.SecretService] the keychain store depends
// on. It exists so the store can be unit tested against a fake implementation
// without a live secret service over dbus — see the fake in the linux tests.
//
// Every method maps to a method on [kc.SecretService]; none expose a
// dbus.BusObject, so a fake never needs to talk to the bus.
type secretService interface {
	Collections() ([]dbus.ObjectPath, error)
	ReadAlias(alias string) (dbus.ObjectPath, error)
	IsLocked(collection dbus.ObjectPath) (bool, error)
	OpenSession(mode kc.AuthenticationMode) (*kc.Session, error)
	CloseSession(session *kc.Session)
	Unlock(items []dbus.ObjectPath) error
	SearchCollection(collection dbus.ObjectPath, attributes kc.Attributes) ([]dbus.ObjectPath, error)
	CreateItem(collection dbus.ObjectPath, properties map[string]dbus.Variant, secret kc.Secret, replaceBehavior kc.ReplaceBehavior) (dbus.ObjectPath, error)
	DeleteItem(item dbus.ObjectPath) error
	GetAttributes(item dbus.ObjectPath) (kc.Attributes, error)
	GetSecret(item dbus.ObjectPath, session kc.Session) ([]byte, error)
	SetItemSecret(item dbus.ObjectPath, secret kc.Secret) error
	SetItemAttributes(item dbus.ObjectPath, attributes kc.Attributes) error
	SetItemLabel(item dbus.ObjectPath, label string) error
	// Available reports whether the secret service backend is reachable,
	// without activating it or prompting the user. It backs the eager
	// availability check in New (see ensureAvailable).
	Available(ctx context.Context) error
	Close() error
}

// the concrete secret service must satisfy the interface the store depends on.
var _ secretService = (*kc.SecretService)(nil)

// newService dials a fresh secret service bound to ctx (see [kc.NewService] for
// what ctx bounds). It is a package var so tests can substitute a fake;
// production always returns a real [kc.SecretService].
var newService = func(ctx context.Context) (secretService, error) { return kc.NewService(ctx) }

// Causes wrapped under the exported [ErrKeychainUnavailable] sentinel. They are
// unexported because no caller branches on the specific cause today; they are
// wrapped (not discarded) so either could be promoted to an exported sentinel
// with zero behavioral change if a caller ever needs to distinguish the two
// failure modes via errors.Is.
var (
	// errSessionBusUnavailable is wrapped when the D-Bus session bus could not
	// be reached (newService returned an error). This is the WSL / headless /
	// DBUS_SESSION_BUS_ADDRESS-unset case where there is no session bus at all,
	// but it also covers a session bus that exists yet cannot be connected to or
	// authenticated against. In every case the Secret Service backend is
	// unreachable, so no keychain operation could succeed.
	errSessionBusUnavailable = errors.New("D-Bus session bus unavailable")

	// errNoSecretServiceOwner is wrapped when the session bus is reachable but
	// no process owns the org.freedesktop.secrets name (no gnome-keyring,
	// kwallet, or other Secret Service daemon is running), detected via
	// NameHasOwner returning false.
	errNoSecretServiceOwner = errors.New("no org.freedesktop.secrets owner on the session bus")
)

// defaultProbeTimeout bounds the availability probe when the caller's context
// carries no deadline of its own, so New stays responsive on a host where the
// backend is unreachable without forcing every caller to set a deadline. A
// caller-supplied deadline always takes precedence.
const defaultProbeTimeout = 2 * time.Second

// ensureAvailable eagerly checks that the secret service backend is reachable,
// so New fails at construction time on a host without a usable keyring (for
// example WSL with no D-Bus session bus, or no gnome-keyring/kwallet running)
// instead of failing on the first operation.
//
// It dials a fresh connection through the newService seam, asks the D-Bus
// daemon whether org.freedesktop.secrets has an owner, and closes the
// connection immediately — preserving the fresh-connection-per-operation
// contract. The probe is prompt-safe and side-effect-free: it never activates
// the backend (newService does not autolaunch a bus), opens a session, or
// touches any collection or item (see [kc.SecretService.Available]).
//
// ctx bounds the probe's connection handshake and the NameHasOwner round-trip
// and lets the caller cancel it (see [kc.NewService] for the one part that is
// not ctx-aware, the raw socket dial). When ctx carries no deadline, the probe
// is capped by defaultProbeTimeout so New stays responsive; a caller-supplied
// deadline always wins.
//
// Every failure is reported under the exported [ErrKeychainUnavailable]
// sentinel, with a more specific unexported cause wrapped underneath where one
// is known.
func ensureAvailable(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultProbeTimeout)
		defer cancel()
	}

	service, err := newService(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w: %w", ErrKeychainUnavailable, errSessionBusUnavailable, err)
	}
	defer func() { _ = service.Close() }()

	if err := service.Available(ctx); err != nil {
		if errors.Is(err, kc.ErrNoSecretService) {
			return fmt.Errorf("%w: %w", ErrKeychainUnavailable, errNoSecretServiceOwner)
		}
		// Transport failure, cancellation, or deadline talking to the bus
		// daemon: surface it under the public sentinel without claiming a
		// specific cause.
		return fmt.Errorf("%w: %w", ErrKeychainUnavailable, err)
	}
	return nil
}

// getDefaultCollection gets the secret service collection dbus object path.
//
// It prefers the loginKeychainObjectPath, since most users on X11 would have
// this available via PAM, see https://wiki.gnome.org/Projects/GnomeKeyring/Pam.
//
// As a fallback it queries the secret service for the default collection.
// It is possible that the host does not have a collection set up, in that case
// the only option is to error.
func getDefaultCollection(service secretService) (dbus.ObjectPath, error) {
	collections, err := service.Collections()
	if err != nil {
		return "", err
	}
	// choose the 'login' collection if it exists
	if slices.Contains(collections, loginKeychainObjectPath) {
		return loginKeychainObjectPath, nil
	}
	// we need to fallback to the default collection
	defaultKeychainObjectPath, err := service.ReadAlias("default")
	if err != nil {
		return "", err
	}

	return resolveDefaultCollection(collections, defaultKeychainObjectPath)
}

// resolveDefaultCollection selects the collection to use given the available
// collections and the object path returned by the 'default' alias lookup.
//
// It is split out from [getDefaultCollection] so the selection logic can be
// unit tested without a live secret service over dbus.
func resolveDefaultCollection(collections []dbus.ObjectPath, aliasPath dbus.ObjectPath) (dbus.ObjectPath, error) {
	// choose the 'login' collection if it exists
	if slices.Contains(collections, loginKeychainObjectPath) {
		return loginKeychainObjectPath, nil
	}

	if !aliasPath.IsValid() {
		return "", errors.New("the default collection object path is invalid")
	}

	// the secret service returns the null path '/' when no collection is
	// assigned to the 'default' alias. This is common on headless hosts where
	// neither the 'login' collection nor a 'default' alias has been set up.
	// The null path is syntactically valid (so IsValid above returns true) but
	// does not point at a real collection, so it must be rejected explicitly.
	if aliasPath == nullObjectPath {
		return "", ErrNoDefaultCollection
	}

	return aliasPath, nil
}

var errCollectionLocked = errors.New("collection is locked")

// isCollectionUnlocked verifies if the collection is unlocked.
//
// It returns the errCollectionLocked error by default if the collection is locked.
// On any other error, it returns the underlying error instead.
func isCollectionUnlocked(collectionPath dbus.ObjectPath, service secretService) error {
	locked, err := service.IsLocked(collectionPath)
	if err != nil {
		return err
	}
	if !locked {
		return nil
	}
	return errCollectionLocked
}

// secretServiceIsLockedError is the D-Bus error name the secret service returns
// when a mutating call (e.g. CreateItem) targets a locked collection.
//
// https://specifications.freedesktop.org/secret-service-spec/latest/errors.html
const secretServiceIsLockedError = "org.freedesktop.Secret.Error.IsLocked"

// isLockedDBusError reports whether err is the secret service's "collection is
// locked" D-Bus error. The lock state is matched on the structured D-Bus error
// name rather than the human-readable message so it is stable across backends
// and locales.
func isLockedDBusError(err error) bool {
	var dbusErr dbus.Error
	return errors.As(err, &dbusErr) && dbusErr.Name == secretServiceIsLockedError
}

// Relock retry tuning. An operation that hits a relocked collection is retried
// with exponential backoff: the relock is a brief race that settles on its own,
// and spacing the attempts out avoids hammering the secret service (or, on a
// password-protected keyring, re-issuing Unlock fast enough to spam the user
// with authentication prompts).
//
// relockRetryMaxDelay caps the backoff growth; with the current
// maxRelockRetries the slept delays are 20,40,80,160,320ms (the cap only takes
// effect once maxRelockRetries reaches 6, where the sixth delay would otherwise
// be 640ms).
const (
	maxRelockRetries     = 5
	relockRetryBaseDelay = 20 * time.Millisecond
	relockRetryMaxDelay  = 500 * time.Millisecond
)

// sleepFn is the sleep seam used by the relock backoff so tests can exercise the
// retry loop without real delays. It is a package-level var with no
// synchronisation, so tests that swap it must not run in parallel.
var sleepFn = time.Sleep

// withRelockRetry runs a collection operation, retrying it with exponential
// backoff when the secret service rejects it because the collection is locked.
//
// The store dials a fresh D-Bus connection for every operation and closes it on
// return. gnome-keyring scopes an unlock to the session that performed it, so
// when a previous operation's connection closes the daemon relocks the
// collection — and that relock can land asynchronously in the middle of a later
// operation, after we have already observed the collection as unlocked but
// before the call against the collection runs. The result is an intermittent
// "Cannot create an item in a locked collection" error even though we unlocked
// moments earlier. IsLocked cannot guard against this because the state changes
// between the check and the call, so we react to the authoritative signal — the
// operation's own locked error — by unlocking again and retrying.
//
// In the common case this is the passwordless auto-unlock path (e.g. the
// PAM-unlocked login keyring), where Unlock returns the null prompt and asks
// the user for nothing. withRelockRetry cannot itself prove the keyring is
// passwordless, so on a password-protected keyring a retry could surface an
// authentication prompt; the bounded retry count and backoff keep that to a
// handful of spaced-out prompts at worst, and a dismissed prompt makes Unlock
// return an error that aborts the loop immediately rather than re-prompting.
func withRelockRetry(service secretService, collectionPath dbus.ObjectPath, op func() error) error {
	err := op()
	delay := relockRetryBaseDelay
	for attempt := 0; attempt < maxRelockRetries && isLockedDBusError(err); attempt++ {
		sleepFn(delay)
		delay = min(delay*2, relockRetryMaxDelay)
		if unlockErr := service.Unlock([]dbus.ObjectPath{collectionPath}); unlockErr != nil {
			// Surface why the retry stopped while preserving errors.Is on the
			// underlying Unlock error (e.g. a dismissed prompt). The original
			// locked error is intentionally dropped: the failed unlock is the
			// actionable cause once we have decided to stop retrying.
			return fmt.Errorf("unlock after relock: %w", unlockErr)
		}
		err = op()
	}
	return err
}

type keychainStore[T store.Secret] struct {
	serviceGroup string
	serviceName  string
	factory      store.Factory[T]
}

func (k *keychainStore[T]) Delete(ctx context.Context, id store.ID) error {
	service, err := newService(ctx)
	if err != nil {
		return err
	}
	// NewService dials a fresh private session-bus connection; close it (and
	// its socket fd) when we return. Deferred before CloseSession so that, by
	// LIFO order, the session is closed first and the connection last.
	defer func() { _ = service.Close() }()

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return err
	}
	defer service.CloseSession(session)

	objectPath, err := getDefaultCollection(service)
	if err != nil {
		return err
	}

	err = isCollectionUnlocked(objectPath, service)
	if err != nil && !errors.Is(err, errCollectionLocked) {
		return err
	}
	if errors.Is(err, errCollectionLocked) {
		if err := service.Unlock([]dbus.ObjectPath{objectPath}); err != nil {
			return err
		}
	}

	attributes := make(map[string]string)
	safelySetMetadata(k.serviceGroup, k.serviceName, attributes)
	safelySetID(id, attributes)

	items, err := service.SearchCollection(objectPath, attributes)
	if err != nil {
		return err
	}

	if len(items) == 0 {
		return nil
	}

	return withRelockRetry(service, objectPath, func() error {
		return service.DeleteItem(items[0])
	})
}

func (k *keychainStore[T]) Get(ctx context.Context, id store.ID) (store.Secret, error) {
	service, err := newService(ctx)
	if err != nil {
		return nil, err
	}
	// NewService dials a fresh private session-bus connection; close it (and
	// its socket fd) when we return. Deferred before CloseSession so that, by
	// LIFO order, the session is closed first and the connection last.
	defer func() { _ = service.Close() }()

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return nil, err
	}
	defer service.CloseSession(session)

	objectPath, err := getDefaultCollection(service)
	if err != nil {
		return nil, err
	}

	err = isCollectionUnlocked(objectPath, service)
	if err != nil && !errors.Is(err, errCollectionLocked) {
		return nil, err
	}
	if errors.Is(err, errCollectionLocked) {
		if err := service.Unlock([]dbus.ObjectPath{objectPath}); err != nil {
			return nil, err
		}
	}

	searchMetadata := make(map[string]string)
	safelySetMetadata(k.serviceGroup, k.serviceName, searchMetadata)
	safelySetID(id, searchMetadata)

	items, err := service.SearchCollection(objectPath, searchMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to search collection: %w", err)
	}

	if len(items) == 0 {
		return nil, store.ErrCredentialNotFound
	}

	attributes, err := service.GetAttributes(items[0])
	if err != nil {
		return nil, err
	}
	safelyCleanMetadata(attributes)

	var value []byte
	err = withRelockRetry(service, objectPath, func() error {
		var getErr error
		value, getErr = service.GetSecret(items[0], *session)
		return getErr
	})
	if err != nil {
		return nil, err
	}
	defer clear(value)

	secret := k.factory(ctx, id)
	if err := secret.SetMetadata(attributes); err != nil {
		return nil, err
	}
	if err := secret.Unmarshal(value); err != nil {
		return nil, err
	}

	return secret, nil
}

func (k *keychainStore[T]) GetAllMetadata(ctx context.Context) (map[store.ID]store.Secret, error) {
	service, err := newService(ctx)
	if err != nil {
		return nil, err
	}
	// NewService dials a fresh private session-bus connection; close it (and
	// its socket fd) when we return. Deferred before CloseSession so that, by
	// LIFO order, the session is closed first and the connection last.
	defer func() { _ = service.Close() }()

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return nil, err
	}
	defer service.CloseSession(session)

	objectPath, err := getDefaultCollection(service)
	if err != nil {
		return nil, err
	}

	err = isCollectionUnlocked(objectPath, service)
	if err != nil && !errors.Is(err, errCollectionLocked) {
		return nil, err
	}
	if errors.Is(err, errCollectionLocked) {
		if err := service.Unlock([]dbus.ObjectPath{objectPath}); err != nil {
			return nil, err
		}
	}

	searchMetadata := make(map[string]string)
	safelySetMetadata(k.serviceGroup, k.serviceName, searchMetadata)

	itemPaths, err := service.SearchCollection(objectPath, searchMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to search collection: %w", err)
	}

	// An empty collection is a valid empty result for "list all", not a miss:
	// return an empty (non-nil) map with a nil error. This matches the macOS and Windows backends, which
	// have no empty-as-error guard.
	credentials := make(map[store.ID]store.Secret, len(itemPaths))
	for _, itemPath := range itemPaths {
		attributes, err := service.GetAttributes(itemPath)
		if err != nil {
			return nil, err
		}

		attrID, ok := attributes["id"]
		if !ok {
			return nil, errors.New("secret attributes does not contain `id` field")
		}

		secretID, err := store.ParseID(attrID)
		if err != nil {
			return nil, err
		}
		safelyCleanMetadata(attributes)

		secret := k.factory(ctx, secretID)
		if err := secret.SetMetadata(attributes); err != nil {
			return nil, err
		}

		credentials[secretID] = secret
	}

	return credentials, nil
}

func (k *keychainStore[T]) Save(ctx context.Context, id store.ID, secret store.Secret) error {
	service, err := newService(ctx)
	if err != nil {
		return err
	}
	// NewService dials a fresh private session-bus connection; close it (and
	// its socket fd) when we return. Deferred before CloseSession so that, by
	// LIFO order, the session is closed first and the connection last.
	defer func() { _ = service.Close() }()

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return err
	}
	defer service.CloseSession(session)

	objectPath, err := getDefaultCollection(service)
	if err != nil {
		return err
	}

	err = isCollectionUnlocked(objectPath, service)
	if err != nil && !errors.Is(err, errCollectionLocked) {
		return err
	}
	if errors.Is(err, errCollectionLocked) {
		if err := service.Unlock([]dbus.ObjectPath{objectPath}); err != nil {
			return err
		}
	}

	value, err := secret.Marshal()
	if err != nil {
		return err
	}
	defer clear(value)

	sessSecret, err := session.NewSecret(value)
	if err != nil {
		return err
	}

	attributes := make(map[string]string)
	maps.Copy(attributes, secret.Metadata())
	safelySetMetadata(k.serviceGroup, k.serviceName, attributes)
	safelySetID(id, attributes)

	label := k.itemLabel(id.String())

	// Find existing items for this identity by the stable triple only
	// {service:group, service:name, id}, never the volatile metadata, so a
	// changed metadata value can never hide a previously-stored item. This is
	// what makes the in-place update below reliable and stops the duplicate
	// accumulation described in issue #446.
	ident := make(map[string]string)
	safelySetMetadata(k.serviceGroup, k.serviceName, ident)
	safelySetID(id, ident)

	items, err := service.SearchCollection(objectPath, ident)
	if err != nil {
		return err
	}

	// Nothing stored yet: create a fresh item.
	if len(items) == 0 {
		properties := kc.NewSecretProperties(label, attributes)
		return withRelockRetry(service, objectPath, func() error {
			_, createErr := service.CreateItem(objectPath, properties, sessSecret, kc.ReplaceBehaviorReplace)
			return createErr
		})
	}

	// Update the first match in place. Its object path is preserved, so the
	// secret is never momentarily absent and no duplicate is minted. Writing the
	// secret value IS the operation, so only its failure fails Save; refreshing
	// the attributes and label and collapsing any pre-existing duplicates are
	// best-effort (the secret is already stored) and must not flip the result.
	primary := items[0]
	if err := withRelockRetry(service, objectPath, func() error {
		return service.SetItemSecret(primary, sessSecret)
	}); err != nil {
		return err
	}
	_ = service.SetItemAttributes(primary, attributes)
	_ = service.SetItemLabel(primary, label)
	for _, dup := range items[1:] {
		// Best-effort, but still relock-aware: a collection that relocks
		// mid-collapse would otherwise leave the duplicates the whole feature
		// exists to drain (see withRelockRetry and issue #446).
		_ = withRelockRetry(service, objectPath, func() error {
			return service.DeleteItem(dup)
		})
	}

	return nil
}

func (k *keychainStore[T]) Upsert(ctx context.Context, id store.ID, secret store.Secret) error {
	return k.Save(ctx, id, secret)
}

// loadSecret fetches the raw secret value for itemPath, zeroes it after use,
// and returns a fully populated Secret. collectionPath is the enclosing
// collection, used to re-unlock if it relocks mid-read (see withRelockRetry).
func (k *keychainStore[T]) loadSecret(
	ctx context.Context,
	id store.ID,
	svc secretService,
	collectionPath, itemPath dbus.ObjectPath,
	session *kc.Session,
	attributes map[string]string,
) (store.Secret, error) {
	var value []byte
	err := withRelockRetry(svc, collectionPath, func() error {
		var getErr error
		value, getErr = svc.GetSecret(itemPath, *session)
		return getErr
	})
	if err != nil {
		return nil, err
	}
	defer clear(value)

	safelyCleanMetadata(attributes)

	secret := k.factory(ctx, id)
	if err := secret.SetMetadata(attributes); err != nil {
		return nil, err
	}
	return secret, secret.Unmarshal(value)
}

//gocyclo:ignore
func (k *keychainStore[T]) Filter(ctx context.Context, pattern store.Pattern) (map[store.ID]store.Secret, error) {
	service, err := newService(ctx)
	if err != nil {
		return nil, err
	}
	// NewService dials a fresh private session-bus connection; close it (and
	// its socket fd) when we return. Deferred before CloseSession so that, by
	// LIFO order, the session is closed first and the connection last.
	defer func() { _ = service.Close() }()

	session, err := service.OpenSession(kc.AuthenticationDHAES)
	if err != nil {
		return nil, err
	}
	defer service.CloseSession(session)

	objectPath, err := getDefaultCollection(service)
	if err != nil {
		return nil, err
	}

	err = isCollectionUnlocked(objectPath, service)
	if err != nil && !errors.Is(err, errCollectionLocked) {
		return nil, err
	}
	if errors.Is(err, errCollectionLocked) {
		if err := service.Unlock([]dbus.ObjectPath{objectPath}); err != nil {
			return nil, err
		}
	}

	attributes := make(map[string]string)
	// add our pattern to the attributes so we can match against items that
	// also contain these items
	// only concrete types are used
	safelySetMetadata(k.serviceGroup, k.serviceName, attributes)

	itemPaths, err := service.SearchCollection(objectPath, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search collection: %w", err)
	}

	if len(itemPaths) == 0 {
		return nil, store.ErrCredentialNotFound
	}

	credentials := make(map[store.ID]store.Secret)
	for _, itemPath := range itemPaths {
		attributes, err := service.GetAttributes(itemPath)
		if err != nil {
			return nil, err
		}

		// it is possible that someone else has stored secrets in the keychain
		// directly without conforming to the store.ID format.
		// We shouldn't error here when these values cannot be retrieved or
		// parsed. Instead we just ignore them and proceed.
		// I guess in future we could at least log them somewhere?
		// but for now, let's just continue with the other items in the store.
		attrID, ok := attributes["id"]
		if !ok {
			continue
		}

		secretID, err := store.ParseID(attrID)
		if err != nil {
			continue
		}

		// filter any secrets we couldn't filter through the keychain API
		if !pattern.Match(secretID) {
			continue
		}

		secret, err := k.loadSecret(ctx, secretID, service, objectPath, itemPath, session, attributes)
		if err != nil {
			return nil, err
		}
		credentials[secretID] = secret
	}

	if len(credentials) == 0 {
		return nil, store.ErrCredentialNotFound
	}

	return credentials, nil
}
