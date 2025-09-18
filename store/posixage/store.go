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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"

	"filippo.io/age"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/posixage/internal/flock"
	"github.com/docker/secrets-engine/store/posixage/internal/secretfile"
	"github.com/docker/secrets-engine/x/logging"
)

type fileStore[T store.Secret] struct {
	filesystem *os.Root
	factory    store.Factory[T]
	l          sync.RWMutex
	*config
}

var _ store.Store = &fileStore[store.Secret]{}

// tryLock is an internal convenience function for acquiring an exclusive
// store lock.
//
// It first attempts to acquire a lock using [sync.RWMutex], then applies
// a file-based lock for process-level coordination. This helps applications
// performing concurrent reads and writes, since acquiring a file lock can
// take time-especially when recovering from a stale lock.
//
// It returns an unlock function that must be called to release the lock.
func (f *fileStore[T]) tryLock(ctx context.Context) (func(), error) {
	f.l.Lock()

	unlock, err := flock.TryLock(ctx, f.filesystem)
	if err != nil {
		return nil, err
	}

	return sync.OnceFunc(func() {
		defer f.l.Unlock()
		if err := unlock(); err != nil {
			f.logger.Errorf("%s", err)
		}
	}), nil
}

// tryRLock is an internal convenience function for acquiring a non-exclusive
// store lock.
//
// It first attempts to acquire a lock using [sync.RWMutex], then applies
// a file-based lock for process-level coordination. This helps applications
// performing concurrent reads and writes, since acquiring a file lock can
// take time-especially when recovering from a stale lock.
//
// It returns an unlock function that must be called to release the lock.
func (f *fileStore[T]) tryRLock(ctx context.Context) (func(), error) {
	f.l.RLock()

	unlock, err := flock.TryRLock(ctx, f.filesystem)
	if err != nil {
		return nil, err
	}

	return sync.OnceFunc(func() {
		defer f.l.RUnlock()
		if err := unlock(); err != nil {
			f.logger.Errorf("%s", err)
		}
	}), nil
}

// decryptSecret attempts to decrypt a secret using the registered
// [secretfile.PromptCaller] functions.
//
// For each registered decryption function, the method:
//  1. Determines the associated [secretfile.KeyType].
//  2. Checks if an encrypted secret with the same key type exists.
//  3. Prompts for a decryption key via the callback.
//  4. Builds an identity and attempts decryption.
//
// The first successful decryption returns the plaintext secret. If no
// matching secret file is found for a registered key type, or if all
// decryption attempts fail, an error is returned.
func (f *fileStore[T]) decryptSecret(ctx context.Context, encryptedSecrets []secretfile.EncryptedSecret) ([]byte, error) {
	for _, prompt := range f.registeredDecryptionFunc {
		keyType, err := getPromptCallerKeyType(prompt)
		if err != nil {
			return nil, err
		}

		index := -1
		for i, v := range encryptedSecrets {
			if v.KeyType == keyType {
				index = i
				break
			}
		}

		if index == -1 {
			return nil, fmt.Errorf("decryption function of type %s was specified, but the file was never encrypted with this type", keyType)
		}

		decryptionKey, err := prompt.Call(ctx)
		if err != nil {
			return nil, err
		}

		identity, err := secretfile.GetIdentity(keyType, string(decryptionKey))
		if err != nil {
			return nil, err
		}

		r, err := age.Decrypt(bytes.NewReader(encryptedSecrets[index].EncryptedData), identity)
		if err != nil {
			f.logger.Errorf("failed to decrypt secret of type :%s", keyType)
			continue
		}

		decryptedSecret, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}

		return decryptedSecret, nil
	}

	return nil, errors.New("could not decrypt secret with provided decryption keys")
}

func (f *fileStore[T]) Delete(ctx context.Context, id store.ID) error {
	unlock, err := f.tryLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	return f.filesystem.RemoveAll(secretfile.IDToDirName(id))
}

func (f *fileStore[T]) Filter(ctx context.Context, pattern store.Pattern) (map[store.ID]store.Secret, error) {
	unlock, err := f.tryRLock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	secrets := map[store.ID]store.Secret{}
	err = fs.WalkDir(f.filesystem.FS(), ".", func(_ string, d fs.DirEntry, _ error) error {
		// skip files, we are only interested in directories
		if !d.IsDir() || d.Name() == "." {
			return nil
		}

		id, err := secretfile.DirNameToID(d.Name())
		// we want to continue to the next directory
		// don't stop because a directory does not conform to the
		// secrets.ID
		if err != nil {
			f.logger.Warnf("could not parse secret ID from directory %s", d.Name())
			return fs.SkipDir
		}

		// a pattern mismatch means we should move on to the next secret
		// or directory in this case.
		if !pattern.Match(id) {
			return fs.SkipDir
		}

		encryptedSecrets, metadata, err := secretfile.RestoreSecret(id, f.filesystem)
		// an error on restoring a secret should not prevent others from
		// being read, let's just log and continue
		if err != nil {
			f.logger.Errorf("could not restore secret: %s. Got error: %s", id.String(), err)
			return fs.SkipDir
		}

		decryptedSecret, err := f.decryptSecret(ctx, encryptedSecrets)
		// perhaps an incorrect decryption key was given?
		// we should abort here.
		if err != nil {
			return err
		}

		secret := f.factory()
		if err := secret.SetMetadata(metadata); err != nil {
			return err
		}
		if err := secret.Unmarshal(decryptedSecret); err != nil {
			return err
		}
		secrets[id] = secret

		// WalkDir should skip the files in the current directory.
		// it should move on to the next directory.
		return fs.SkipDir
	})
	if err != nil {
		return nil, err
	}

	if len(secrets) == 0 {
		return nil, store.ErrCredentialNotFound
	}
	return secrets, nil
}

func (f *fileStore[T]) Get(ctx context.Context, id store.ID) (store.Secret, error) {
	unlock, err := f.tryRLock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	encryptedSecrets, metadata, err := secretfile.RestoreSecret(id, f.filesystem)
	if err != nil {
		return nil, err
	}

	decryptedSecret, err := f.decryptSecret(ctx, encryptedSecrets)
	if err != nil {
		return nil, err
	}

	secret := f.factory()
	if err := secret.SetMetadata(metadata); err != nil {
		return nil, err
	}
	if err := secret.Unmarshal(decryptedSecret); err != nil {
		return nil, err
	}
	return secret, nil
}

func (f *fileStore[T]) GetAllMetadata(ctx context.Context) (map[store.ID]store.Secret, error) {
	unlock, err := f.tryRLock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	secrets := map[store.ID]store.Secret{}
	err = fs.WalkDir(f.filesystem.FS(), ".", func(path string, d fs.DirEntry, _ error) error {
		// skip files, we are only interested in directories
		if !d.IsDir() || d.Name() == "." {
			return nil
		}

		id, err := secretfile.DirNameToID(d.Name())
		// just continue to the next item, we don't want to stop because
		// a directory failed to get decoded to a secrets.ID.
		if err != nil {
			f.logger.Warnf("could not parse directory name (%s) to secret ID: %s", path, err)
			return fs.SkipDir
		}

		secretDir, err := f.filesystem.OpenRoot(d.Name())
		if err != nil {
			return err
		}
		defer func() {
			_ = secretDir.Close()
		}()

		metadata, err := secretfile.RestoreMetadata(id, secretDir)
		if err != nil {
			return err
		}

		secret := f.factory()
		if err := secret.SetMetadata(metadata); err != nil {
			return err
		}
		secrets[id] = secret

		// WalkDir should skip the files in the current directory.
		// it should move on to the next directory.
		return fs.SkipDir
	})
	if err != nil {
		return nil, err
	}

	if len(secrets) == 0 {
		return nil, store.ErrCredentialNotFound
	}
	return secrets, nil
}

func (f *fileStore[T]) Save(ctx context.Context, id store.ID, s store.Secret) error {
	unlock, err := f.tryLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	// we need to get the encryption keys from the caller, this is a blocking
	// call and we must wait for the caller to cancel the ctx or wait for the
	// user to complete the interaction.
	keyGroups, err := promptForEncryptionKeys(ctx, f.registeredEncryptionFuncs)
	if err != nil {
		return err
	}

	secret, err := s.Marshal()
	if err != nil {
		return err
	}
	metadata := s.Metadata()

	var secrets []secretfile.EncryptedSecret
	// each encryption key must be be used within its group - age does not
	// support multiple encryption keys of different types, (e.g. age + password)
	// however, multiple encryption keys of the same type can be used (e.g. password + password)
	for k, encryptionKeys := range keyGroups {
		recipients, err := secretfile.GetRecipients(k, encryptionKeys)
		if err != nil {
			return err
		}

		var encryptedSecret bytes.Buffer
		w, err := age.Encrypt(&encryptedSecret, recipients...)
		if err != nil {
			return err
		}

		if _, err := w.Write(secret); err != nil {
			return err
		}

		// encrypt the last chunk and flush to our buffer, this must be called.
		if err := w.Close(); err != nil {
			return err
		}

		secrets = append(secrets, secretfile.EncryptedSecret{
			KeyType:       k,
			EncryptedData: encryptedSecret.Bytes(),
		})
	}

	return secretfile.Persist(id, f.filesystem, metadata, secrets)
}

type config struct {
	logger                    logging.Logger
	registeredDecryptionFunc  []secretfile.PromptCaller
	registeredEncryptionFuncs []secretfile.PromptCaller
}

type Options func(c *config) error

// WithLogger adds a custom logger to the store.
// If a no logger has been specified, a noop logger is used instead.
func WithLogger(l logging.Logger) Options {
	return func(c *config) error {
		c.logger = l
		return nil
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
	return func(c *config) error {
		c.registeredEncryptionFuncs = append(c.registeredEncryptionFuncs, secretfile.PromptCaller(callback))
		return nil
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
	return func(c *config) error {
		c.registeredDecryptionFunc = append(c.registeredDecryptionFunc, secretfile.PromptCaller(callback))
		return nil
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
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	if len(cfg.registeredEncryptionFuncs) == 0 {
		return nil, errors.New("requires at least one encryption callback function to be registered")
	}
	if len(cfg.registeredDecryptionFunc) == 0 {
		return nil, errors.New("requires at least one decryption callback function to be registered")
	}
	store.config = cfg

	return store, nil
}
