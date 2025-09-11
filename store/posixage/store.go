// Package posixage provides a file-based secret store secured with
// [age](https://github.com/FiloSottile/age) encryption.
//
// Secrets are stored in directories named after a base64-encoded secret ID.
// Each secret can be encrypted with one or more encryption keys. When
// retrieving a secret, one or more corresponding decryption keys may be
// provided to unlock it.
//
// This allows flexible key management, supporting scenarios such as
// multiple recipients, key rotation, or shared access.
package posixage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"

	"filippo.io/age"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/logging"
)

type fileStore[T store.Secret] struct {
	filesystem                *os.Root
	registeredEncryptionFuncs []callbackFunc
	registeredDecryptionFunc  []callbackFunc
	factory                   store.Factory[T]
	l                         sync.RWMutex

	logger logging.Logger
}

var _ store.Store = &fileStore[store.Secret]{}

type secretFile struct {
	fileName      string
	encryptedData []byte
}

type secretDirectory struct {
	// rootName is a base64 encoding of the secret ID
	rootName string
	metadata map[string]string
	secrets  []secretFile
}

func newSecretDirectory(id store.ID) *secretDirectory {
	return &secretDirectory{
		rootName: base64.StdEncoding.EncodeToString([]byte(id.String())),
	}
}

const (
	secretFileName   = "secret"
	metadataFileName = "metadata.json"
)

// atomicWrite writes the file to a temporary file first and upon successful write
// renames the file.
// This function does not guarantee concurrent writes and does not clean temporary
// files upon failure.
func atomicWrite(fs *os.Root, fileName string, data []byte) error {
	tmpFileName := fileName + ".tmp"
	tmpFile, err := fs.Create(tmpFileName)
	if err != nil {
		return err
	}
	defer func() {
		_ = tmpFile.Close()
	}()

	if _, err = tmpFile.Write(data); err != nil {
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		return err
	}

	if err := fs.Rename(tmpFileName, fileName); err != nil {
		return err
	}

	return nil
}

func (f *secretDirectory) rootExists(fs *os.Root) bool {
	_, err := fs.Stat(f.rootName)
	return err == nil
}

// save creates the secret and metadata files inside its own directory.
// The directory name is a base64 encoded string of the secret ID.
// If the directory does not exist, it is created.
// Any failure to write the files will result in the removal of the directory.
func (f *secretDirectory) save(fs *os.Root) error {
	// always delete the entire directory.
	// since we support multiple encryption keys we should keep them synchronized
	// to prevent some existing files from containing old data.
	if f.rootExists(fs) {
		if err := f.delete(fs); err != nil {
			return err
		}
	}

	if err := fs.Mkdir(f.rootName, 0o700); err != nil {
		return err
	}

	root, err := fs.OpenRoot(f.rootName)
	if err != nil {
		return err
	}

	meta, err := json.Marshal(f.metadata)
	if err != nil {
		return err
	}

	if err := atomicWrite(root, metadataFileName, meta); err != nil {
		_ = fs.RemoveAll(f.rootName)
		return err
	}

	for _, s := range f.secrets {
		if err := atomicWrite(root, s.fileName, s.encryptedData); err != nil {
			_ = fs.RemoveAll(f.rootName)
			return err
		}
	}

	return nil
}

// delete removes the entire directory including any child directories
func (f *secretDirectory) delete(fs *os.Root) error {
	return fs.RemoveAll(f.rootName)
}

// restore reads the secret and metadata files from its scoped directory
func (f *secretDirectory) restore(filesystem *os.Root) error {
	root, err := filesystem.OpenRoot(f.rootName)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
	}()

	metadataStore, err := root.Open(metadataFileName)
	if err != nil {
		return err
	}
	defer metadataStore.Close()

	b, err := io.ReadAll(metadataStore)
	if err != nil {
		return err
	}

	var metadata map[string]string
	if err := json.Unmarshal(b, &metadata); err != nil {
		return err
	}

	f.metadata = metadata

	files, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if !strings.HasPrefix(file.Name(), secretFileName) {
			continue
		}
		encryptedData, err := root.ReadFile(file.Name())
		if err != nil {
			continue
		}
		sec := secretFile{
			fileName:      file.Name(),
			encryptedData: encryptedData,
		}
		f.secrets = append(f.secrets, sec)
	}

	return nil
}

func (f *secretDirectory) restoreMetadata(fs *os.Root) error {
	root, err := fs.OpenRoot(f.rootName)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
	}()

	metadataStore, err := root.Open(metadataFileName)
	if err != nil {
		return err
	}
	defer metadataStore.Close()

	b, err := io.ReadAll(metadataStore)
	if err != nil {
		return err
	}

	var metadata map[string]string
	if err := json.Unmarshal(b, &metadata); err != nil {
		return err
	}

	f.metadata = metadata

	return nil
}

// sortSecrets sorts the secrets in order of callback funcs
func sortSecrets(secrets []secretFile, registeredFuncs []callbackFunc) {
	// sort the secrets in order of callback funcs
	alreadyMatched := map[string]struct{}{}
	var secretsIdx int
	for _, registeredFunc := range registeredFuncs {
		k := string(getCallbackFuncName(registeredFunc))
		if _, ok := alreadyMatched[k]; ok {
			continue
		}
		for i := range secrets {
			// get the keyType and match it against the callbackFunc keyType
			if k == strings.TrimPrefix(secrets[i].fileName, secretFileName) {
				alreadyMatched[k] = struct{}{}
				secrets[secretsIdx], secrets[i] = secrets[i], secrets[secretsIdx]
				secretsIdx++
				break
			}
		}
	}
}

func decryptSecret(ctx context.Context, secrets []secretFile, registeredDecryptionFunc []callbackFunc) ([]byte, error) {
	group, err := groupCallbackFuncs(ctx, registeredDecryptionFunc)
	if err != nil {
		return nil, err
	}

	sortSecrets(secrets, registeredDecryptionFunc)

	for _, s := range secrets {
		var identities []age.Identity
		groupType := keyType(strings.TrimPrefix(s.fileName, secretFileName))
		values, ok := group[groupType]
		if !ok {
			continue
		}

		for _, v := range values {
			identity, err := getIdentity(groupType, v)
			if err != nil {
				return nil, err
			}
			identities = append(identities, identity)
		}

		r, err := age.Decrypt(bytes.NewReader(s.encryptedData), identities...)
		if err != nil {
			return nil, err
		}

		decryptedSecret, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}

		return decryptedSecret, nil
	}

	return nil, errors.New("could not decrypt secret with provided keys")
}

func (f *fileStore[T]) Delete(_ context.Context, id store.ID) error {
	f.l.Lock()
	defer f.l.Unlock()

	encFile := newSecretDirectory(id)
	return encFile.delete(f.filesystem)
}

func (f *fileStore[T]) Filter(ctx context.Context, pattern store.Pattern) (map[store.ID]store.Secret, error) {
	fsDirectories, err := fs.ReadDir(f.filesystem.FS(), ".")
	if err != nil {
		return nil, err
	}
	if len(fsDirectories) == 0 {
		return nil, store.ErrCredentialNotFound
	}

	secrets := make(map[store.ID]store.Secret)
	for _, dir := range fsDirectories {
		if !dir.IsDir() {
			continue
		}

		s, err := base64.StdEncoding.DecodeString(dir.Name())
		if err != nil {
			return nil, err
		}
		id, err := store.ParseID(string(s))
		if err != nil {
			continue
		}

		if !pattern.Match(id) {
			continue
		}

		encFile := secretDirectory{
			rootName: dir.Name(),
		}

		if err := encFile.restore(f.filesystem); err != nil {
			continue
		}

		decryptedSecret, err := decryptSecret(ctx, encFile.secrets, f.registeredDecryptionFunc)
		if err != nil {
			return nil, err
		}

		secret := f.factory()
		if err := secret.SetMetadata(encFile.metadata); err != nil {
			return nil, err
		}
		if err := secret.Unmarshal(decryptedSecret); err != nil {
			return nil, err
		}
		secrets[id] = secret
	}
	if len(secrets) == 0 {
		return nil, store.ErrCredentialNotFound
	}
	return secrets, nil
}

func (f *fileStore[T]) Get(ctx context.Context, id store.ID) (store.Secret, error) {
	f.l.Lock()
	defer f.l.Unlock()

	encFile := newSecretDirectory(id)

	if err := encFile.restore(f.filesystem); err != nil {
		return nil, err
	}

	decryptedSecret, err := decryptSecret(ctx, encFile.secrets, f.registeredDecryptionFunc)
	if err != nil {
		return nil, err
	}

	secret := f.factory()
	if err := secret.SetMetadata(encFile.metadata); err != nil {
		return nil, err
	}
	if err := secret.Unmarshal(decryptedSecret); err != nil {
		return nil, err
	}
	return secret, nil
}

func (f *fileStore[T]) GetAllMetadata(_ context.Context) (map[store.ID]store.Secret, error) {
	f.l.Lock()
	defer f.l.Unlock()

	fsDirectories, err := fs.ReadDir(f.filesystem.FS(), ".")
	if err != nil {
		return nil, err
	}
	if len(fsDirectories) == 0 {
		return nil, store.ErrCredentialNotFound
	}

	secrets := map[store.ID]store.Secret{}
	for _, dir := range fsDirectories {
		if !dir.IsDir() {
			continue
		}

		s, err := base64.StdEncoding.DecodeString(dir.Name())
		if err != nil {
			return nil, err
		}

		id, err := store.ParseID(string(s))
		if err != nil {
			continue
		}

		encFile := secretDirectory{
			rootName: dir.Name(),
		}

		if err := encFile.restoreMetadata(f.filesystem); err != nil {
			return nil, err
		}

		secret := f.factory()
		if err := secret.SetMetadata(encFile.metadata); err != nil {
			return nil, err
		}
		secrets[id] = secret
	}

	if len(secrets) == 0 {
		return nil, store.ErrCredentialNotFound
	}
	return secrets, nil
}

func (f *fileStore[T]) Save(ctx context.Context, id store.ID, s store.Secret) error {
	f.l.Lock()
	defer f.l.Unlock()

	groups, err := groupCallbackFuncs(ctx, f.registeredEncryptionFuncs)
	if err != nil {
		return err
	}

	val, err := s.Marshal()
	if err != nil {
		return err
	}
	metadata := s.Metadata()

	var secrets []secretFile
	for g, values := range groups {
		fileName := secretFileName + string(g)

		var recipients []age.Recipient
		for _, value := range values {
			recipient, err := getRecipient(g, value)
			if err != nil {
				return err
			}
			recipients = append(recipients, recipient)
		}

		var encryptedSecret bytes.Buffer
		w, err := age.Encrypt(&encryptedSecret, recipients...)
		if err != nil {
			return err
		}
		defer func() {
			_ = w.Close()
		}()

		if _, err := w.Write(val); err != nil {
			return err
		}

		if err := w.Close(); err != nil {
			return err
		}

		secrets = append(secrets, secretFile{
			fileName:      fileName,
			encryptedData: encryptedSecret.Bytes(),
		})
	}

	encFile := newSecretDirectory(id)
	encFile.metadata = metadata
	encFile.secrets = secrets
	return encFile.save(f.filesystem)
}

type config struct {
	logger                    logging.Logger
	registeredDecryptionFunc  []callbackFunc
	registeredEncryptionFuncs []callbackFunc
}

type Options func(c *config)

// WithLogger adds a custom logger to the store.
// If a no logger has been specified, a noop logger is used instead.
func WithLogger[T store.Secret](l logging.Logger) Options {
	return func(c *config) {
		c.logger = l
	}
}

type encryptionFuncs interface {
	EncryptionPassword | EncryptionSSH | EncryptionAgeX25519
}

// WithEncryptionCallbackFunc registers a callback used to prompt the user
// for input when encrypting credentials.
//
// Multiple callbacks may be registered. They are invoked in the same order
// they were added.
func WithEncryptionCallbackFunc[K encryptionFuncs](callback K) Options {
	return func(c *config) {
		c.registeredEncryptionFuncs = append(c.registeredEncryptionFuncs, callbackFunc(callback))
	}
}

type decryptionFuncs interface {
	DecryptionPassword | DecryptionSSH | DecryptionAgeX25519
}

// WithDecryptionCallbackFunc registers a callback used to prompt the user
// for input when decrypting credentials.
//
// Multiple callbacks may be registered. They are invoked in the same order
// they were added.
func WithDecryptionCallbackFunc[K decryptionFuncs](callback K) Options {
	return func(c *config) {
		c.registeredDecryptionFunc = append(c.registeredDecryptionFunc, callbackFunc(callback))
	}
}

// New returns a [store.Store] that manages encrypted files on disk.
//
// Each secret is stored in its own directory, named with a base64-encoded
// secret ID. The directory contains:
//   - one encrypted secret file for each configured encryption key type
//   - a metadata file, which is public and always formatted as valid JSON
func New[T store.Secret](rootDir *os.Root, f store.Factory[T], opts ...Options) (store.Store, error) {
	store := &fileStore[T]{
		filesystem: rootDir,
		factory:    f,
	}

	cfg := &config{
		logger: &noopLogger{},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if len(cfg.registeredEncryptionFuncs) == 0 {
		return nil, errors.New("requires at least one encryption callback function to be registered")
	}
	if len(cfg.registeredDecryptionFunc) == 0 {
		return nil, errors.New("requires at least one decryption callback function to be registered")
	}

	store.registeredEncryptionFuncs = cfg.registeredEncryptionFuncs
	store.registeredDecryptionFunc = cfg.registeredDecryptionFunc
	store.logger = cfg.logger

	return store, nil
}
