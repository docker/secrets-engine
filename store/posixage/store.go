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

	unlock, err := flock.TryLock(logging.WithLogger(ctx, f.logger), f.filesystem)
	if err != nil {
		f.l.Unlock()
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

	unlock, err := flock.TryRLock(logging.WithLogger(ctx, f.logger), f.filesystem)
	if err != nil {
		f.l.RUnlock()
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
// [promptCaller] functions.
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

		decryptionKey, err := prompt.call(ctx)
		if err != nil {
			return nil, err
		}

		plaintext, err := f.tryDecrypt(keyType, decryptionKey, encryptedSecrets[index].EncryptedData)
		if err != nil {
			f.logger.Errorf("failed to decrypt secret of type :%s", keyType)
			continue
		}
		return plaintext, nil
	}

	return nil, errors.New("could not decrypt secret with provided decryption keys")
}

// tryDecrypt uses decryptionKey to decrypt encryptedData, zeroing the key after
// use regardless of outcome.
func (f *fileStore[T]) tryDecrypt(keyType secretfile.KeyType, decryptionKey, encryptedData []byte) ([]byte, error) {
	defer clear(decryptionKey)

	identity, err := secretfile.GetIdentity(keyType, string(decryptionKey))
	if err != nil {
		return nil, err
	}

	r, err := age.Decrypt(bytes.NewReader(encryptedData), identity)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(r)
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
		defer clear(decryptedSecret)

		secret := f.factory(ctx, id)
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
	defer clear(decryptedSecret)

	secret := f.factory(ctx, id)
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

		metadata, err := secretfile.RestoreMetadata(secretDir)
		if err != nil {
			return err
		}

		secret := f.factory(ctx, id)
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
	defer clear(secret)
	metadata := s.Metadata()

	var secrets []secretfile.EncryptedSecret
	// Encryption keys must be grouped by type. The age library does not
	// support mixing different key types in a single encryption operation
	// (e.g., age + password). However, multiple keys of the same type are
	// allowed (e.g., password + password).
	for k, encryptionKeys := range keyGroups {
		recipients, err := secretfile.GetRecipients(k, encryptionKeys, secretfile.WithScryptWorkFactor(f.scryptWorkFactor))
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

		// Finalize encryption and flush all data into the buffer.
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

func (f *fileStore[T]) Upsert(ctx context.Context, id store.ID, s store.Secret) error {
	return f.Save(ctx, id, s)
}

type config struct {
	logger                    logging.Logger
	registeredDecryptionFunc  []promptCaller
	registeredEncryptionFuncs []promptCaller
	// scryptWorkFactor is the scrypt work factor (2^logN) applied to
	// password-protected secrets. A zero value uses the age default.
	scryptWorkFactor int
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

// WithScryptWorkFactor sets the scrypt work factor (2^logN) used when
// encrypting password-protected secrets. A higher value increases the cost of
// brute-forcing the passphrase at the expense of encryption and decryption
// time.
//
// age fixes the other scrypt parameters at r=8, p=1, so only N=2^logN varies.
// Each increment of logN doubles both the derivation time and the memory
// required: derivation time is roughly linear in N (age calibrates logN=18 at
// about one second on a modern machine), and memory usage is exactly 2^logN
// KiB. The following table is anchored to age's own calibration; absolute times
// are approximate and vary by CPU, but the ratios are exact powers of two:
//
//	logN  memory    ~time/unlock  attacker cost vs. 18
//	----  --------  ------------  --------------------
//	 8    256 KiB   ~1 ms         1024x cheaper
//	10    1 MiB     ~4 ms         256x cheaper
//	12    4 MiB     ~16 ms        64x cheaper
//	14    16 MiB    ~60 ms        16x cheaper
//	15    32 MiB    ~125 ms       8x cheaper
//	16    64 MiB    ~250 ms       4x cheaper
//	17    128 MiB   ~500 ms       2x cheaper  (OWASP minimum)
//	18    256 MiB   ~1 s          baseline    (age default)
//	20    1 GiB     ~4 s          4x dearer
//	22    4 GiB     ~16 s         16x dearer   (MaxScryptWorkFactor)
//
// Guidance on choosing a value:
//
//   - The work factor is only a linear multiplier on the attacker's cost per
//     guess; the passphrase's own entropy dominates security. A low-entropy,
//     guessable passphrase is not rescued by a high work factor, and genuinely
//     high-entropy random key material is safe even at a low one.
//   - OWASP's Password Storage guidance recommends a minimum of N=2^17 (logN
//     17) with r=8, p=1 for human-chosen passphrases. Values at or below logN
//     12 fit in CPU cache, lose scrypt's memory-hardness, and degrade toward a
//     plain fast hash that GPUs and ASICs can attack in parallel; reserve them
//     for high-entropy key material or tests.
//   - Pick the highest logN whose derivation time is tolerable on the weakest
//     device that must unlock a secret (each unlock pays the cost once). Note
//     that memory is consumed per concurrent derivation, so logN=20 costs 1 GiB
//     per in-flight unlock and can exhaust constrained hosts.
//   - Lowering the work factor is a deliberate security downgrade; make sure the
//     inputs are high-entropy before doing so.
//
// Valid values are 1..[secretfile.MaxScryptWorkFactor]. Values above the
// maximum are rejected because the default age decryption work-factor ceiling
// is 22; files written with a higher factor could not be decrypted by standard
// age tooling. If unset, the age default (logN=18) is used.
//
// This option only affects password keys; it is a no-op for age and ssh keys.
// Because the work factor is recorded in each file's header, changing it does
// not affect the ability to decrypt secrets written with a previous value; the
// new factor applies only to secrets written after the change.
func WithScryptWorkFactor(logN int) Options {
	return func(c *config) error {
		if logN < 1 || logN > secretfile.MaxScryptWorkFactor {
			return fmt.Errorf("scrypt work factor out of range (1..%d): %d", secretfile.MaxScryptWorkFactor, logN)
		}
		c.scryptWorkFactor = logN
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
		c.registeredEncryptionFuncs = append(c.registeredEncryptionFuncs, promptCaller(callback))
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
		c.registeredDecryptionFunc = append(c.registeredDecryptionFunc, promptCaller(callback))
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
