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

package keychain

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"maps"
	"strconv"
	"strings"

	"github.com/danieljoos/wincred"
	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"

	"github.com/docker/secrets-engine/store"
)

var (
	ErrCredentialBadUsername      = errors.New("credential username is invalid")
	ErrInvalidCredentialFlags     = errors.New("an invalid flag was specified for the flags parameter")
	ErrInvalidCredentialParameter = errors.New("protected field does not match provided value for an existing credential")
	ErrNoLogonSession             = errors.New("logon session does not exist or there is no credential set associated with this logon session")
	sysErrInvalidCredentialFlags  = windows.ERROR_INVALID_FLAGS
	sysErrNoSuchLogonSession      = windows.ERROR_NO_SUCH_LOGON_SESSION
)

const (
	// maxBlobSize is the maximum size of a Windows Credential Manager blob
	// (CRED_MAX_CREDENTIAL_BLOB_SIZE = 5 * 512 bytes).
	maxBlobSize = 2560

	// chunkCountKey is stored in the primary credential's attributes when a
	// secret's encoded blob exceeds maxBlobSize and must be split.
	chunkCountKey = "chunk:count"

	// chunkIndexKey is stored in each chunk credential's attributes to
	// identify it as a chunk and record its position.
	chunkIndexKey = "chunk:index"
)

// encodeSecret marshals the secret into a slice of bytes in UTF16 format
func encodeSecret(secret store.Secret) ([]byte, error) {
	data, err := secret.Marshal()
	if err != nil {
		return nil, err
	}

	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	blob, _, err := transform.Bytes(encoder, data)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// decodeSecret unmarshals the secret from UTF16 format to UTF8
// secret will contain the unmarshaled value.
func decodeSecret(blob []byte, secret store.Secret) error {
	decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	val, _, err := transform.Bytes(decoder, blob)
	if err != nil {
		return err
	}

	return secret.Unmarshal(val)
}

// chunkBlob splits blob into consecutive slices each at most size bytes long.
func chunkBlob(blob []byte, size int) [][]byte {
	var chunks [][]byte
	for len(blob) > 0 {
		n := min(size, len(blob))
		chunks = append(chunks, blob[:n])
		blob = blob[n:]
	}
	return chunks
}

// isChunkCredential reports whether the given attributes belong to a chunk
// credential (as opposed to a primary credential).
func isChunkCredential(attrs []wincred.CredentialAttribute) bool {
	for _, attr := range attrs {
		if attr.Keyword == chunkIndexKey {
			return true
		}
	}
	return false
}

type keychainStore[T store.Secret] struct {
	serviceGroup string
	serviceName  string
	factory      store.Factory[T]
}

// itemChunkLabel returns the target name for the i-th chunk of a secret.
func (k *keychainStore[T]) itemChunkLabel(id store.ID, index int) string {
	return fmt.Sprintf("%s:chunk:%d", k.itemLabel(id.String()), index)
}

// readChunks fetches count chunk credentials for id and concatenates their
// raw CredentialBlob bytes in order.
func (k *keychainStore[T]) readChunks(id store.ID, count int) ([]byte, error) {
	var blob []byte
	for i := range count {
		gc, err := wincred.GetGenericCredential(k.itemChunkLabel(id, i))
		if err != nil {
			return nil, mapWindowsCredentialError(err)
		}
		blob = append(blob, gc.CredentialBlob...)
	}
	return blob, nil
}

// deleteChunks removes chunk credentials for id until none remain.
// It is safe to call when no chunks exist.
func (k *keychainStore[T]) deleteChunks(id store.ID) error {
	for i := 0; ; i++ {
		g := wincred.NewGenericCredential(k.itemChunkLabel(id, i))
		err := g.Delete()
		if err != nil {
			if errors.Is(err, wincred.ErrElementNotFound) {
				return nil
			}
			return mapWindowsCredentialError(err)
		}
	}
}

func (k *keychainStore[T]) Delete(_ context.Context, id store.ID) error {
	if err := k.deleteChunks(id); err != nil {
		return err
	}
	g := wincred.NewGenericCredential(k.itemLabel(id.String()))
	err := g.Delete()
	if err != nil && !errors.Is(err, wincred.ErrElementNotFound) {
		return mapWindowsCredentialError(err)
	}
	return nil
}

func (k *keychainStore[T]) Get(ctx context.Context, id store.ID) (store.Secret, error) {
	gc, err := wincred.GetGenericCredential(k.itemLabel(id.String()))
	if err != nil {
		return nil, mapWindowsCredentialError(err)
	}

	attributes := mapFromWindowsAttributes(gc.Attributes)

	// Determine the raw UTF-16 blob before safelyCleanMetadata strips chunkCountKey.
	var rawBlob []byte
	if countStr, ok := attributes[chunkCountKey]; ok {
		count, err := strconv.Atoi(countStr)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk count %q: %w", countStr, err)
		}
		rawBlob, err = k.readChunks(id, count)
		if err != nil {
			return nil, err
		}
	} else {
		rawBlob = gc.CredentialBlob
	}

	safelyCleanMetadata(attributes)

	secret := k.factory(ctx, id)
	if err := secret.SetMetadata(attributes); err != nil {
		return nil, err
	}
	if err := decodeSecret(rawBlob, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// isServiceCredential checks if a credential attribute contains the
// [serviceGroupKey] and [serviceNameKey] attribute.
//
// The keychainStore serviceGroup and serviceName should match what is stored
// in the attributes.
func isServiceCredential[T store.Secret](k *keychainStore[T], attrs []wincred.CredentialAttribute) bool {
	// must have both serviceGroup and serviceName
	var (
		serviceName  string
		serviceGroup string
	)
	for _, attr := range attrs {
		switch attr.Keyword {
		case serviceGroupKey:
			serviceGroup = string(attr.Value)
		case serviceNameKey:
			serviceName = string(attr.Value)
		}
	}
	return strings.EqualFold(serviceGroup, k.serviceGroup) && strings.EqualFold(serviceName, k.serviceName)
}

// findServiceCredentials is an iterator that yields credentials that match the
// service group and service name.
func findServiceCredentials[T store.Secret](k *keychainStore[T], pattern store.Pattern, credentials []*wincred.Credential) iter.Seq[*wincred.Credential] {
	return func(yield func(cred *wincred.Credential) bool) {
		for _, c := range credentials {
			if isChunkCredential(c.Attributes) {
				continue
			}
			if !isServiceCredential(k, c.Attributes) {
				continue
			}
			id, err := store.ParseID(c.UserName)
			if err != nil {
				continue
			}
			if !pattern.Match(id) {
				continue
			}
			if !yield(c) {
				return
			}
		}
	}
}

func mapToWindowsAttributes(attributes map[string]string) []wincred.CredentialAttribute {
	winAttrs := make([]wincred.CredentialAttribute, 0, len(attributes))
	for k, v := range attributes {
		winAttrs = append(winAttrs, wincred.CredentialAttribute{
			Keyword: k,
			Value:   []byte(v),
		})
	}
	return winAttrs
}

func mapFromWindowsAttributes(winAttrs []wincred.CredentialAttribute) map[string]string {
	attributes := make(map[string]string, len(winAttrs))
	for _, attr := range winAttrs {
		attributes[attr.Keyword] = string(attr.Value)
	}
	return attributes
}

func (k *keychainStore[T]) GetAllMetadata(ctx context.Context) (map[store.ID]store.Secret, error) {
	credentials, err := wincred.List()
	if err != nil {
		return nil, mapWindowsCredentialError(err)
	}

	onlyLabelPrefix := k.itemLabel("")

	// this pattern matches any secret ID that conforms to the secrets engine
	pattern := store.MustParsePattern("**")

	secrets := make(map[store.ID]store.Secret)
	for cred := range findServiceCredentials(k, pattern, credentials) {
		id, err := store.ParseID(strings.ReplaceAll(cred.TargetName, onlyLabelPrefix, ""))
		if err != nil {
			return nil, err
		}

		attributes := mapFromWindowsAttributes(cred.Attributes)
		safelyCleanMetadata(attributes)

		secret := k.factory(ctx, id)
		if err := secret.SetMetadata(attributes); err != nil {
			return nil, err
		}
		secrets[id] = secret
	}

	return secrets, nil
}

func (k *keychainStore[T]) Save(_ context.Context, id store.ID, secret store.Secret) error {
	blob, err := encodeSecret(secret)
	if err != nil {
		return err
	}

	attributes := make(map[string]string)
	maps.Copy(attributes, secret.Metadata())
	safelySetMetadata(k.serviceGroup, k.serviceName, attributes)
	safelySetID(id, attributes)

	// Always remove stale chunk credentials before writing, so that a
	// previously-chunked secret that now fits in a single blob leaves no
	// orphaned chunk credentials behind (and vice-versa).
	if err := k.deleteChunks(id); err != nil {
		return err
	}

	g := wincred.NewGenericCredential(k.itemLabel(id.String()))
	g.UserName = id.String()
	g.Persist = wincred.PersistLocalMachine

	// the blob is too large, we will chunk it across multiple entries
	if len(blob) > maxBlobSize {
		// Write chunk credentials for the oversized blob.
		chunks := chunkBlob(blob, maxBlobSize)
		for i, chunk := range chunks {
			gc := wincred.NewGenericCredential(k.itemChunkLabel(id, i))
			gc.UserName = id.String()
			gc.CredentialBlob = chunk
			gc.Persist = wincred.PersistLocalMachine
			gc.Attributes = mapToWindowsAttributes(map[string]string{
				chunkIndexKey: strconv.Itoa(i),
			})
			if err := mapWindowsCredentialError(gc.Write()); err != nil {
				return err
			}
		}
		// Write the primary credential with metadata and the chunk count.
		// The blob is stored in chunk credentials only.
		attributes[chunkCountKey] = strconv.Itoa(len(chunks))
	} else {
		g.CredentialBlob = blob
	}

	g.Attributes = mapToWindowsAttributes(attributes)
	return mapWindowsCredentialError(g.Write())
}

func (k *keychainStore[T]) Filter(ctx context.Context, pattern store.Pattern) (map[store.ID]store.Secret, error) {
	// Note: there is no notion of a filter on Windows inside the wincred API.
	// It has no way to even filter on known attributes.
	// This means we need to retrieve the entire list of ALL secrets, that
	// may or may not even be related to our serviceName, serviceGroup, or
	// keychain instance.
	// The performance of this shouldn't be too terrible as we don't fetch
	// the encrypted secret from the keychain unless it matches our pattern.

	credentials, err := wincred.List()
	if err != nil {
		return nil, mapWindowsCredentialError(err)
	}

	onlyLabelPrefix := k.itemLabel("")

	secrets := make(map[store.ID]store.Secret)
	for cred := range findServiceCredentials(k, pattern, credentials) {
		// it is possible that someone else has stored secrets in the keychain
		// directly without conforming to the store.ID format.
		// We shouldn't error here when these values cannot be retrieved or
		// parsed. Instead we just ignore them and proceed.
		// I guess in future we could at least log them somewhere?
		// but for now, let's just continue with the other items in the store.
		id, err := store.ParseID(strings.ReplaceAll(cred.TargetName, onlyLabelPrefix, ""))
		if err != nil {
			continue
		}

		gc, err := wincred.GetGenericCredential(cred.TargetName)
		if err != nil {
			return nil, mapWindowsCredentialError(err)
		}

		gcAttributes := mapFromWindowsAttributes(gc.Attributes)

		// Determine the raw UTF-16 blob before safelyCleanMetadata strips chunkCountKey.
		var rawBlob []byte
		if countStr, ok := gcAttributes[chunkCountKey]; ok {
			count, err := strconv.Atoi(countStr)
			if err != nil {
				return nil, fmt.Errorf("invalid chunk count %q: %w", countStr, err)
			}
			rawBlob, err = k.readChunks(id, count)
			if err != nil {
				return nil, err
			}
		} else {
			rawBlob = gc.CredentialBlob
		}

		safelyCleanMetadata(gcAttributes)

		secret := k.factory(ctx, id)
		if err := secret.SetMetadata(gcAttributes); err != nil {
			return nil, err
		}

		decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		blob, _, err := transform.Bytes(decoder, rawBlob)
		if err != nil {
			return nil, err
		}

		if err := secret.Unmarshal(blob); err != nil {
			return nil, err
		}
		secrets[id] = secret
	}

	return secrets, nil
}

func mapWindowsCredentialError(err error) error {
	switch err {
	case wincred.ErrElementNotFound:
		return store.ErrCredentialNotFound
	case wincred.ErrBadUsername:
		return ErrCredentialBadUsername
	case wincred.ErrInvalidParameter:
		return ErrInvalidCredentialParameter
	case sysErrInvalidCredentialFlags:
		return ErrInvalidCredentialFlags
	case sysErrNoSuchLogonSession:
		return ErrNoLogonSession
	}
	return err
}
