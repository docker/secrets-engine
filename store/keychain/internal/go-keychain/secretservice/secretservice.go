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
	conn               *dbus.Conn
	signalCh           <-chan *dbus.Signal
	sessionOpenTimeout time.Duration
}

// Session
type Session struct {
	Mode    AuthenticationMode
	Path    dbus.ObjectPath
	Public  *big.Int
	Private *big.Int
	AESKey  []byte
}

// DefaultSessionOpenTimeout
const DefaultSessionOpenTimeout = 10 * time.Second

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
	_ = conn.AddMatchSignal(dbus.WithMatchOption("org.freedesktop.Secret.Prompt", "Completed"))
	return &SecretService{conn: conn, signalCh: signalCh, sessionOpenTimeout: DefaultSessionOpenTimeout}, nil
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

// SetSessionOpenTimeout
func (s *SecretService) SetSessionOpenTimeout(d time.Duration) {
	s.sessionOpenTimeout = d
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
	collectionsProperty  = "org.freedesktop.Secret.Service.Collections"
	readAliasMethod      = "org.freedesktop.Secret.Service.ReadAlias"
	collectionLockedProp = "org.freedesktop.Secret.Collection.Locked"
)

// Collections returns the object paths of every collection known to the secret
// service.
func (s *SecretService) Collections() ([]dbus.ObjectPath, error) {
	variant, err := s.ServiceObj().GetProperty(collectionsProperty)
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
func (s *SecretService) ReadAlias(alias string) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	if err := s.ServiceObj().Call(readAliasMethod, NilFlags, alias).Store(&path); err != nil {
		return "", err
	}
	return path, nil
}

// IsLocked reports whether the given collection is currently locked.
func (s *SecretService) IsLocked(collection dbus.ObjectPath) (bool, error) {
	variant, err := s.Obj(collection).GetProperty(collectionLockedProp)
	if err != nil {
		return false, err
	}
	locked, ok := variant.Value().(bool)
	if !ok {
		return false, errors.New("unexpected type for collection locked property")
	}
	return locked, nil
}

type sessionOpenResponse struct {
	algorithmOutput dbus.Variant
	path            dbus.ObjectPath
}

func (s *SecretService) openSessionRaw(mode AuthenticationMode, sessionAlgorithmInput dbus.Variant) (resp sessionOpenResponse, err error) {
	err = s.ServiceObj().
		Call("org.freedesktop.Secret.Service.OpenSession", NilFlags, mode, sessionAlgorithmInput).
		Store(&resp.algorithmOutput, &resp.path)
	if err != nil {
		return sessionOpenResponse{}, fmt.Errorf("failed to open secretservice session: %w", err)
	}
	return resp, nil
}

// OpenSession
func (s *SecretService) OpenSession(mode AuthenticationMode) (session *Session, err error) {
	var sessionAlgorithmInput dbus.Variant

	session = new(Session)

	session.Mode = mode

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
		sessionAlgorithmInput = dbus.MakeVariant(public.Bytes()) // math/big.Int.Bytes is big endian
	default:
		return nil, fmt.Errorf("unknown authentication mode %v", mode)
	}

	sessionOpenCh := make(chan sessionOpenResponse)
	errCh := make(chan error)
	go func() {
		resp, err := s.openSessionRaw(mode, sessionAlgorithmInput)
		if err != nil {
			errCh <- err
		} else {
			sessionOpenCh <- resp
		}
	}()

	var sessionAlgorithmOutput dbus.Variant
	// NOTE: If the timeout case is reached, the above goroutine is leaked.
	// This is not terrible because D-Bus calls have an internal 2-mintue
	// timeout, so the goroutine will finish eventually. If two OpenSessions
	// are called at the saime time, they'll be on different channels so
	// they won't interfere with each other.
	select {
	case resp := <-sessionOpenCh:
		sessionAlgorithmOutput = resp.algorithmOutput
		session.Path = resp.path
	case err := <-errCh:
		return nil, err
	case <-time.After(s.sessionOpenTimeout):
		return nil, fmt.Errorf("timed out after %s", s.sessionOpenTimeout)
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
func (s *SecretService) CloseSession(session *Session) {
	s.Obj(session.Path).Call("org.freedesktop.Secret.Session.Close", NilFlags)
}

// SearchCollection
func (s *SecretService) SearchCollection(collection dbus.ObjectPath, attributes Attributes) (items []dbus.ObjectPath, err error) {
	err = s.Obj(collection).
		Call("org.freedesktop.Secret.Collection.SearchItems", NilFlags, attributes).
		Store(&items)
	if err != nil {
		return nil, fmt.Errorf("failed to search collection: %w", err)
	}
	return items, nil
}

// ReplaceBehavior
type ReplaceBehavior int

// ReplaceBehaviorDoNotReplace
const ReplaceBehaviorDoNotReplace = 0

// ReplaceBehaviorReplace
const ReplaceBehaviorReplace = 1

// CreateItem
func (s *SecretService) CreateItem(collection dbus.ObjectPath, properties map[string]dbus.Variant, secret Secret, replaceBehavior ReplaceBehavior) (item dbus.ObjectPath, err error) {
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
	err = s.Obj(collection).
		Call("org.freedesktop.Secret.Collection.CreateItem", NilFlags, properties, secret, replace).
		Store(&item, &prompt)
	if err != nil {
		return "", fmt.Errorf("failed to create item: %w", err)
	}
	_, err = s.PromptAndWait(prompt)
	if err != nil {
		return "", err
	}
	return item, nil
}

// DeleteItem
func (s *SecretService) DeleteItem(item dbus.ObjectPath) (err error) {
	var prompt dbus.ObjectPath
	err = s.Obj(item).
		Call("org.freedesktop.Secret.Item.Delete", NilFlags).
		Store(&prompt)
	if err != nil {
		return fmt.Errorf("failed to delete item: %w", err)
	}
	_, err = s.PromptAndWait(prompt)
	if err != nil {
		return err
	}
	return nil
}

// GetAttributes
func (s *SecretService) GetAttributes(item dbus.ObjectPath) (attributes Attributes, err error) {
	attributesV, err := s.Obj(item).GetProperty("org.freedesktop.Secret.Item.Attributes")
	if err != nil {
		return nil, fmt.Errorf("failed to get attributes: %w", err)
	}
	attributesMap, ok := attributesV.Value().(map[string]string)
	if !ok {
		return nil, errors.New("failed to coerce item attributes")
	}
	return Attributes(attributesMap), nil
}

// GetSecret
func (s *SecretService) GetSecret(item dbus.ObjectPath, session Session) (secretPlaintext []byte, err error) {
	var secretI []interface{}
	err = s.Obj(item).
		Call("org.freedesktop.Secret.Item.GetSecret", NilFlags, session.Path).
		Store(&secretI)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
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

// Unlock
func (s *SecretService) Unlock(items []dbus.ObjectPath) (err error) {
	var dummy []dbus.ObjectPath
	var prompt dbus.ObjectPath
	err = s.ServiceObj().
		Call("org.freedesktop.Secret.Service.Unlock", NilFlags, items).
		Store(&dummy, &prompt)
	if err != nil {
		return fmt.Errorf("failed to unlock items: %w", err)
	}
	_, err = s.PromptAndWait(prompt)
	if err != nil {
		return fmt.Errorf("failed to prompt: %w", err)
	}
	return nil
}

// LockItems
func (s *SecretService) LockItems(items []dbus.ObjectPath) (err error) {
	var dummy []dbus.ObjectPath
	var prompt dbus.ObjectPath
	err = s.ServiceObj().
		Call("org.freedesktop.Secret.Service.Lock", NilFlags, items).
		Store(&dummy, &prompt)
	if err != nil {
		return fmt.Errorf("failed to lock items: %w", err)
	}
	_, err = s.PromptAndWait(prompt)
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

// PromptAndWait is NOT thread-safe.
func (s *SecretService) PromptAndWait(prompt dbus.ObjectPath) (paths *dbus.Variant, err error) {
	if prompt == NullPrompt {
		return nil, nil
	}
	call := s.Obj(prompt).Call("org.freedesktop.Secret.Prompt.Prompt", NilFlags, "Keyring Prompt")
	if call.Err != nil {
		return nil, fmt.Errorf("failed to prompt: %w", call.Err)
	}
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
		case <-time.After(30 * time.Second):
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
func (s *SecretService) SetItemSecret(item dbus.ObjectPath, secret Secret) error {
	if err := s.Obj(item).Call("org.freedesktop.Secret.Item.SetSecret", NilFlags, secret).Store(); err != nil {
		return fmt.Errorf("failed to set item secret: %w", err)
	}
	return nil
}

// SetItemAttributes replaces an existing item's lookup attributes in place by
// setting the read-write org.freedesktop.Secret.Item.Attributes property
// (type a{ss}) through org.freedesktop.DBus.Properties.Set. The collection must
// be unlocked.
func (s *SecretService) SetItemAttributes(item dbus.ObjectPath, attributes Attributes) error {
	if err := s.Obj(item).SetProperty("org.freedesktop.Secret.Item.Attributes", dbus.MakeVariant(map[string]string(attributes))); err != nil {
		return fmt.Errorf("failed to set item attributes: %w", err)
	}
	return nil
}

// SetItemLabel replaces an existing item's displayable label in place by setting
// the read-write org.freedesktop.Secret.Item.Label property (type s) through
// org.freedesktop.DBus.Properties.Set. The collection must be unlocked.
func (s *SecretService) SetItemLabel(item dbus.ObjectPath, label string) error {
	if err := s.Obj(item).SetProperty("org.freedesktop.Secret.Item.Label", dbus.MakeVariant(label)); err != nil {
		return fmt.Errorf("failed to set item label: %w", err)
	}
	return nil
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
