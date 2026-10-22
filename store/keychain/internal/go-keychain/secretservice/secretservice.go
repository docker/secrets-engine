package secretservice

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	dbus "github.com/godbus/dbus/v5"
)

// SecretServiceInterface
const SecretServiceInterface = "org.freedesktop.secrets"

// SecretServiceObjectPath
const SecretServiceObjectPath dbus.ObjectPath = "/org/freedesktop/secrets"

// DefaultCollection need not necessarily exist in the user's keyring.
const DefaultCollection dbus.ObjectPath = "/org/freedesktop/secrets/aliases/default"

// AuthenticationMode
type AuthenticationMode string

// AuthenticationInsecurePlain
const AuthenticationInsecurePlain AuthenticationMode = "plain"

// AuthenticationDHAES
const AuthenticationDHAES AuthenticationMode = "dh-ietf1024-sha256-aes128-cbc-pkcs7"

// NilFlags
const NilFlags = 0

// Attributes
type Attributes map[string]string

// Secret
type Secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// PromptCompletedResult
type PromptCompletedResult struct {
	Dismissed bool
	Paths     dbus.Variant
}

// SecretService
type SecretService struct {
	conn     *dbus.Conn
	signalCh <-chan *dbus.Signal
}

// Session
type Session struct {
	Mode    AuthenticationMode
	Path    dbus.ObjectPath
	Public  *big.Int
	Private *big.Int
	AESKey  []byte
}

// defaultCallTimeout is used when the caller's context has no deadline set.
const defaultCallTimeout = 10 * time.Second

// callContext accepts a context with a deadline, if the context has no
// deadline, the default [defaultCallTimeout] is set instead.
func callContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, defaultCallTimeout)
}

// ErrNoSessionBus is returned by [NewService] when no D-Bus session bus can be
// reached: either DBUS_SESSION_BUS_ADDRESS names a unix socket that does not
// exist, or no session bus address can be determined without launching one. The
// keychain package wraps it under its ErrKeychainUnavailable sentinel.
var ErrNoSessionBus = errors.New("no D-Bus session bus available")

// NewService dials a fresh private connection to the D-Bus session bus and
// returns a [SecretService] bound to it. Every call dials its own connection, so
// the caller MUST Close the returned service (see [SecretService.Close]).
//
// ctx bounds the connection's Auth and Hello handshake and every subsequent
// D-Bus call issued on it: cancelling ctx tears the connection down (godbus
// closes it when ctx is done). NewService never autolaunches a session bus — it
// uses [dbus.SessionBusPrivateNoAutoStartup] rather than dbus.ConnectSessionBus,
// so on a host with no running bus (WSL, headless) it fails fast with
// [ErrNoSessionBus] instead of spawning dbus-launch. As a further fast path it
// stats the session bus unix socket before dialing and returns [ErrNoSessionBus]
// if that socket is missing.
//
// NOTE: the raw socket dial itself is performed by godbus and is not ctx-aware;
// ctx bounds everything after the connection is established. In practice a unix
// socket dial fails immediately when the socket is missing or unaccepting, and
// the pre-dial stat covers the common stale-address case.
func NewService(ctx context.Context) (*SecretService, error) {
	if paths, missing := sessionBusMissingSocket(); missing {
		return nil, fmt.Errorf("%w: no session bus socket exists (%s)", ErrNoSessionBus, paths)
	}
	conn, err := dbus.SessionBusPrivateNoAutoStartup(dbus.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSessionBus, err)
	}
	if err := conn.Auth(nil); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to authenticate to dbus session bus: %w", err)
	}
	if err := conn.Hello(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to complete dbus Hello handshake: %w", err)
	}
	signalCh := make(chan *dbus.Signal, 16)
	conn.Signal(signalCh)
	// Without this subscription the bus never delivers Prompt.Completed and
	// PromptAndWait times out on every real (non-null) prompt.
	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.Secret.Prompt"),
		dbus.WithMatchMember("Completed"),
	); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to subscribe to prompt completion signals: %w", err)
	}
	return &SecretService{conn: conn, signalCh: signalCh}, nil
}

// sessionBusMissingSocket reports whether DBUS_SESSION_BUS_ADDRESS names one or
// more session bus endpoints and *every* one is a unix socket path that does not
// exist — the only case where dialing is guaranteed to fail, so NewService can
// fail fast without paying for a dial. The returned string lists the missing
// paths for the error message.
//
// It returns ("", false) — "cannot rule the bus out, dial normally" — whenever
// the address is unset or "autolaunch:", OR any endpoint is not a stat-able unix
// path (an abstract socket, a tcp endpoint, or an unparseable entry), OR any unix
// path's socket exists. This deliberately mirrors godbus, which tries each
// ';'-separated endpoint in turn and uses the first that connects: we only
// short-circuit when no endpoint could possibly connect.
func sessionBusMissingSocket() (string, bool) {
	addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if addr == "" || addr == "autolaunch:" {
		return "", false
	}
	var missing []string
	for entry := range strings.SplitSeq(addr, ";") {
		if entry == "" {
			continue
		}
		path, ok := unixSocketPath(entry)
		if !ok {
			// Not a stat-able unix path (abstract, tcp, unparseable): this
			// endpoint might connect, so let godbus dial rather than guess.
			return "", false
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			// Socket exists, or stat failed for another reason (e.g. a
			// permission quirk): this endpoint might connect, so dial normally.
			return "", false
		}
		missing = append(missing, path)
	}
	if len(missing) == 0 {
		return "", false
	}
	return strings.Join(missing, ", "), true
}

// unixSocketPath returns the filesystem path of a single "transport:key=val,..."
// address entry, with ok=true, when it is a "unix:...path=" endpoint. It returns
// ok=false for abstract unix sockets (which have no filesystem path to stat),
// non-unix transports (tcp, ...), and any entry with no path key.
func unixSocketPath(entry string) (string, bool) {
	if !strings.HasPrefix(entry, "unix:") {
		return "", false
	}
	for kv := range strings.SplitSeq(strings.TrimPrefix(entry, "unix:"), ",") {
		key, value, found := strings.Cut(kv, "=")
		if found && key == "path" {
			if unescaped, err := dbus.UnescapeBusAddressValue(value); err == nil {
				return unescaped, true
			}
			return value, true
		}
	}
	return "", false
}

// Close releases the underlying D-Bus connection and its socket file
// descriptor. Each [NewService] call dials a private session-bus connection, so
// every service MUST be closed when it is no longer needed; otherwise the
// connection — and its fd — leaks for the lifetime of the process. Closing the
// connection also tears down the signal goroutine that NewService starts. Close
// is safe to call on a service whose connection is nil.
func (s *SecretService) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// ErrNoSecretService is returned by [SecretService.Available] when no process
// owns the org.freedesktop.secrets name on the session bus, i.e. no Secret
// Service backend (such as gnome-keyring or kwallet) is currently running. The
// keychain package wraps it under its ErrKeychainUnavailable sentinel.
var ErrNoSecretService = errors.New("no org.freedesktop.secrets owner on the session bus")

// nameHasOwnerMethod is the org.freedesktop.DBus daemon method that reports
// whether a bus name currently has an owner.
const nameHasOwnerMethod = "org.freedesktop.DBus.NameHasOwner"

// Available reports whether the Secret Service backend is reachable, without
// activating it or producing any user-facing prompt.
//
// It issues a single org.freedesktop.DBus.NameHasOwner query against the bus
// daemon object ([dbus.Conn.BusObject]). Prompt-safety comes from the nature of
// that call: NameHasOwner is answered by the bus daemon from its own name
// registry and is never forwarded to org.freedesktop.secrets, so it cannot reach
// any prompt path (see [PromptAndWait]) and cannot mutate the keyring.
// [dbus.FlagNoAutoStart] is passed as defence-in-depth, but note it has no effect
// on this particular call: the destination is the always-running bus daemon
// (org.freedesktop.DBus), not an activatable service, so there is nothing for the
// flag to suppress here.
//
// It returns nil when the name is owned, [ErrNoSecretService] when it is not,
// or the underlying error on a transport failure or a ctx timeout.
func (s *SecretService) Available(ctx context.Context) error {
	if s == nil || s.conn == nil {
		return errors.New("secret service connection is not open")
	}
	var hasOwner bool
	if err := s.conn.BusObject().
		CallWithContext(ctx, nameHasOwnerMethod, dbus.FlagNoAutoStart, SecretServiceInterface).
		Store(&hasOwner); err != nil {
		return err
	}
	if !hasOwner {
		return ErrNoSecretService
	}
	return nil
}

// ServiceObj
func (s *SecretService) ServiceObj() dbus.BusObject {
	return s.conn.Object(SecretServiceInterface, SecretServiceObjectPath)
}

// Obj
func (s *SecretService) Obj(path dbus.ObjectPath) dbus.BusObject {
	return s.conn.Object(SecretServiceInterface, path)
}

// dbus interface members used by the high-level helpers below.
//
// https://specifications.freedesktop.org/secret-service-spec/latest/index.html
const (
	secretServiceInterfaceName    = "org.freedesktop.Secret.Service"
	secretCollectionInterfaceName = "org.freedesktop.Secret.Collection"
	secretItemInterfaceName       = "org.freedesktop.Secret.Item"
	collectionsProperty           = "Collections"
	collectionLockedProp          = "Locked"
	itemAttributesProperty        = "Attributes"
	itemLabelProperty             = "Label"
	readAliasMethod               = "org.freedesktop.Secret.Service.ReadAlias"
	propertiesGetMethod           = "org.freedesktop.DBus.Properties.Get"
	propertiesSetMethod           = "org.freedesktop.DBus.Properties.Set"
)

func call(ctx context.Context, obj dbus.BusObject, failure, method string, args []any, retvalues ...any) error {
	callCtx, cancel := callContext(ctx)
	defer cancel()
	if err := obj.CallWithContext(callCtx, method, NilFlags, args...).Store(retvalues...); err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("%s: timed out after %s: %w", failure, defaultCallTimeout, err)
		}
		return fmt.Errorf("%s: %w", failure, err)
	}
	return nil
}

func (s *SecretService) getProperty(ctx context.Context, obj dbus.BusObject, interfaceName, property string) (dbus.Variant, error) {
	var variant dbus.Variant
	failure := fmt.Sprintf("failed to get property %s.%s", interfaceName, property)
	if err := call(ctx, obj, failure, propertiesGetMethod, []any{interfaceName, property}, &variant); err != nil {
		return dbus.Variant{}, err
	}
	return variant, nil
}

// Collections returns the object paths of every collection known to the secret
// service. ctx bounds the round-trip (see [callContext]).
func (s *SecretService) Collections(ctx context.Context) ([]dbus.ObjectPath, error) {
	variant, err := s.getProperty(ctx, s.ServiceObj(), secretServiceInterfaceName, collectionsProperty)
	if err != nil {
		return nil, err
	}
	collections, ok := variant.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, errors.New("could not list keychain collections")
	}
	return collections, nil
}

// ReadAlias resolves an alias (e.g. "default") to the collection object path it
// points at. The secret service returns the null path "/" when the alias is not
// assigned to any collection.
func (s *SecretService) ReadAlias(ctx context.Context, alias string) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	if err := call(ctx, s.ServiceObj(), fmt.Sprintf("failed to read alias %q", alias), readAliasMethod, []any{alias}, &path); err != nil {
		return "", err
	}
	return path, nil
}

// IsLocked reports whether the given collection is currently locked.
func (s *SecretService) IsLocked(ctx context.Context, collection dbus.ObjectPath) (bool, error) {
	variant, err := s.getProperty(ctx, s.Obj(collection), secretCollectionInterfaceName, collectionLockedProp)
	if err != nil {
		return false, err
	}
	locked, ok := variant.Value().(bool)
	if !ok {
		return false, errors.New("unexpected type for collection locked property")
	}
	return locked, nil
}

func (s *SecretService) OpenSession(ctx context.Context, mode AuthenticationMode) (*Session, error) {
	session := &Session{Mode: mode}
	var sessionAlgorithmInput dbus.Variant
	switch mode {
	case AuthenticationInsecurePlain:
		sessionAlgorithmInput = dbus.MakeVariant("")
	case AuthenticationDHAES:
		group := rfc2409SecondOakleyGroup()
		private, public, err := group.NewKeypair()
		if err != nil {
			return nil, err
		}
		session.Private = private
		session.Public = public
		sessionAlgorithmInput = dbus.MakeVariant(group.encode(public))
	default:
		return nil, fmt.Errorf("unknown authentication mode %v", mode)
	}

	var sessionAlgorithmOutput dbus.Variant
	if err := call(ctx, s.ServiceObj(), "failed to open secretservice session",
		"org.freedesktop.Secret.Service.OpenSession", []any{mode, sessionAlgorithmInput},
		&sessionAlgorithmOutput, &session.Path); err != nil {
		return nil, err
	}

	switch mode {
	case AuthenticationInsecurePlain:
	case AuthenticationDHAES:
		theirPublicBigEndian, ok := sessionAlgorithmOutput.Value().([]byte)
		if !ok {
			return nil, errors.New("failed to coerce algorithm output value to byteslice")
		}
		group := rfc2409SecondOakleyGroup()
		theirPublic := new(big.Int)
		theirPublic.SetBytes(theirPublicBigEndian)
		aesKey, err := group.keygenHKDFSHA256AES128(theirPublic, session.Private)
		if err != nil {
			return nil, err
		}
		session.AESKey = aesKey
	default:
		return nil, fmt.Errorf("unknown authentication mode %v", mode)
	}

	return session, nil
}

// CloseSession
func (s *SecretService) CloseSession(ctx context.Context, session *Session) {
	_ = call(ctx, s.Obj(session.Path), "failed to close session", "org.freedesktop.Secret.Session.Close", nil)
}

// SearchCollection
func (s *SecretService) SearchCollection(ctx context.Context, collection dbus.ObjectPath, attributes Attributes) (items []dbus.ObjectPath, err error) {
	if err := call(ctx, s.Obj(collection), "failed to search collection",
		"org.freedesktop.Secret.Collection.SearchItems", []any{attributes}, &items); err != nil {
		return nil, err
	}
	return items, nil
}

// ReplaceBehavior
type ReplaceBehavior int

// ReplaceBehaviorDoNotReplace
const ReplaceBehaviorDoNotReplace = 0

// ReplaceBehaviorReplace
const ReplaceBehaviorReplace = 1

// CreateItem creates an item in the collection; ctx bounds the prompt wait.
func (s *SecretService) CreateItem(
	ctx context.Context,
	collection dbus.ObjectPath,
	properties map[string]dbus.Variant,
	secret Secret,
	replaceBehavior ReplaceBehavior,
) (item dbus.ObjectPath, err error) {
	var replace bool
	switch replaceBehavior {
	case ReplaceBehaviorDoNotReplace:
		replace = false
	case ReplaceBehaviorReplace:
		replace = true
	default:
		return "", fmt.Errorf("unknown replace behavior %d", replaceBehavior)
	}

	var prompt dbus.ObjectPath
	if err := call(ctx, s.Obj(collection), "failed to create item",
		"org.freedesktop.Secret.Collection.CreateItem", []any{properties, secret, replace},
		&item, &prompt); err != nil {
		return "", err
	}
	_, err = s.PromptAndWait(ctx, prompt)
	if err != nil {
		return "", err
	}
	return item, nil
}

// DeleteItem deletes an item; ctx bounds the prompt wait.
func (s *SecretService) DeleteItem(ctx context.Context, item dbus.ObjectPath) (err error) {
	var prompt dbus.ObjectPath
	if err := call(ctx, s.Obj(item), "failed to delete item", "org.freedesktop.Secret.Item.Delete", nil, &prompt); err != nil {
		return err
	}
	_, err = s.PromptAndWait(ctx, prompt)
	if err != nil {
		return err
	}
	return nil
}

// GetAttributes
func (s *SecretService) GetAttributes(ctx context.Context, item dbus.ObjectPath) (attributes Attributes, err error) {
	attributesV, err := s.getProperty(ctx, s.Obj(item), secretItemInterfaceName, itemAttributesProperty)
	if err != nil {
		return nil, err
	}
	attributesMap, ok := attributesV.Value().(map[string]string)
	if !ok {
		return nil, errors.New("failed to coerce item attributes")
	}
	return Attributes(attributesMap), nil
}

// GetSecret
func (s *SecretService) GetSecret(ctx context.Context, item dbus.ObjectPath, session Session) (secretPlaintext []byte, err error) {
	var secretI []interface{}
	if err := call(ctx, s.Obj(item), "failed to get secret",
		"org.freedesktop.Secret.Item.GetSecret", []any{session.Path}, &secretI); err != nil {
		return nil, err
	}
	secret := new(Secret)
	err = dbus.Store(secretI, &secret.Session, &secret.Parameters, &secret.Value, &secret.ContentType)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal get secret result: %w", err)
	}

	switch session.Mode {
	case AuthenticationInsecurePlain:
		secretPlaintext = secret.Value
	case AuthenticationDHAES:
		plaintext, err := unauthenticatedAESCBCDecrypt(secret.Parameters, secret.Value, session.AESKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secret: %w", err)
		}
		secretPlaintext = plaintext
	default:
		return nil, fmt.Errorf("cannot make secret for authentication mode %v", session.Mode)
	}

	return secretPlaintext, nil
}

// NullPrompt
const NullPrompt = "/"

// Unlock unlocks the given collections or items; ctx bounds the prompt wait.
func (s *SecretService) Unlock(ctx context.Context, items []dbus.ObjectPath) (err error) {
	var dummy []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := call(ctx, s.ServiceObj(), "failed to unlock items",
		"org.freedesktop.Secret.Service.Unlock", []any{items}, &dummy, &prompt); err != nil {
		return err
	}
	_, err = s.PromptAndWait(ctx, prompt)
	if err != nil {
		return fmt.Errorf("failed to prompt: %w", err)
	}
	return nil
}

// LockItems locks the given collections or items; ctx bounds the prompt wait.
func (s *SecretService) LockItems(ctx context.Context, items []dbus.ObjectPath) (err error) {
	var dummy []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := call(ctx, s.ServiceObj(), "failed to lock items",
		"org.freedesktop.Secret.Service.Lock", []any{items}, &dummy, &prompt); err != nil {
		return err
	}
	_, err = s.PromptAndWait(ctx, prompt)
	if err != nil {
		return fmt.Errorf("failed to prompt: %w", err)
	}
	return nil
}

// PromptDismissedError
type PromptDismissedError struct {
	err error
}

// Error
func (p PromptDismissedError) Error() string {
	return p.err.Error()
}

// promptTimeout caps how long PromptAndWait waits for a prompt to complete.
const promptTimeout = 30 * time.Second

// PromptAndWait displays the prompt and blocks until it completes, is
// dismissed, ctx is done, or promptTimeout elapses. A NullPrompt returns
// immediately.
//
// PromptAndWait is NOT thread-safe.
func (s *SecretService) PromptAndWait(ctx context.Context, prompt dbus.ObjectPath) (paths *dbus.Variant, err error) {
	if prompt == NullPrompt {
		return nil, nil
	}
	if err := call(ctx, s.Obj(prompt), "failed to prompt", "org.freedesktop.Secret.Prompt.Prompt", []any{"Keyring Prompt"}); err != nil {
		return nil, err
	}
	// created once, outside the loop, so unrelated signals cannot reset it
	timeout := time.After(promptTimeout)
	for {
		var result PromptCompletedResult
		select {
		case signal, ok := <-s.signalCh:
			if !ok {
				return nil, errors.New("prompt channel closed")
			}
			if signal == nil {
				continue
			}
			if signal.Name != "org.freedesktop.Secret.Prompt.Completed" {
				continue
			}
			err = dbus.Store(signal.Body, &result.Dismissed, &result.Paths)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal prompt result: %w", err)
			}
			if result.Dismissed {
				return nil, PromptDismissedError{errors.New("prompt dismissed")}
			}
			return &result.Paths, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("prompt aborted: %w", ctx.Err())
		case <-timeout:
			return nil, errors.New("prompt timed out")
		}
	}
}

// SetItemSecret replaces an existing item's secret value in place via
// org.freedesktop.Secret.Item.SetSecret. The secret must already be encoded for
// the session it references (see [Session.NewSecret]). SetSecret takes a single
// Secret argument (D-Bus signature (oayays)) and returns no values, so there is
// no prompt path: the item's collection must be unlocked first (use [Unlock]),
// otherwise the call fails.
func (s *SecretService) SetItemSecret(ctx context.Context, item dbus.ObjectPath, secret Secret) error {
	return call(ctx, s.Obj(item), "failed to set item secret", "org.freedesktop.Secret.Item.SetSecret", []any{secret})
}

// SetItemAttributes replaces an existing item's lookup attributes in place by
// setting the read-write org.freedesktop.Secret.Item.Attributes property
// (type a{ss}) through org.freedesktop.DBus.Properties.Set. The collection must
// be unlocked.
func (s *SecretService) SetItemAttributes(ctx context.Context, item dbus.ObjectPath, attributes Attributes) error {
	value := dbus.MakeVariant(map[string]string(attributes))
	return call(ctx, s.Obj(item), "failed to set item attributes", propertiesSetMethod,
		[]any{secretItemInterfaceName, itemAttributesProperty, value})
}

// SetItemLabel replaces an existing item's displayable label in place by setting
// the read-write org.freedesktop.Secret.Item.Label property (type s) through
// org.freedesktop.DBus.Properties.Set. The collection must be unlocked.
func (s *SecretService) SetItemLabel(ctx context.Context, item dbus.ObjectPath, label string) error {
	return call(ctx, s.Obj(item), "failed to set item label", propertiesSetMethod,
		[]any{secretItemInterfaceName, itemLabelProperty, dbus.MakeVariant(label)})
}

// NewSecretProperties
func NewSecretProperties(label string, attributes map[string]string) map[string]dbus.Variant {
	return map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant(label),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(attributes),
	}
}

// NewSecret
func (session *Session) NewSecret(secretBytes []byte) (Secret, error) {
	switch session.Mode {
	case AuthenticationInsecurePlain:
		return Secret{
			Session:     session.Path,
			Parameters:  nil,
			Value:       secretBytes,
			ContentType: "application/octet-stream",
		}, nil
	case AuthenticationDHAES:
		iv, ciphertext, err := unauthenticatedAESCBCEncrypt(secretBytes, session.AESKey)
		if err != nil {
			return Secret{}, err
		}
		return Secret{
			Session:     session.Path,
			Parameters:  iv,
			Value:       ciphertext,
			ContentType: "application/octet-stream",
		}, nil
	default:
		return Secret{}, fmt.Errorf("cannot make secret for authentication mode %v", session.Mode)
	}
}
