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

package commands

import (
	"errors"
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pass "github.com/docker/secrets-engine/plugins/pass/store"
	"github.com/docker/secrets-engine/plugins/pass/teststore"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
)

func TestWrapKeychainErrors(t *testing.T) {
	t.Parallel()
	locked := fmt.Errorf("get 'foo': %w", keychain.ErrCollectionLocked)

	t.Run("locked error from RunE carries the hint", func(t *testing.T) {
		cmd := wrapKeychainErrors(&cobra.Command{
			RunE: func(*cobra.Command, []string) error { return locked },
		})
		err := cmd.RunE(cmd, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, keychain.ErrCollectionLocked)
		assert.ErrorContains(t, err, "get 'foo'")
		assert.ErrorContains(t, err, lockedKeychainHint)
	})

	t.Run("locked error from PreRunE carries the hint", func(t *testing.T) {
		cmd := wrapKeychainErrors(&cobra.Command{
			PreRunE: func(*cobra.Command, []string) error { return locked },
		})
		err := cmd.PreRunE(cmd, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, keychain.ErrCollectionLocked)
		assert.ErrorContains(t, err, lockedKeychainHint)
	})

	t.Run("duplicate error from RunE carries the hint", func(t *testing.T) {
		dup := fmt.Errorf("save 'foo': %w", keychain.ErrDuplicateItem)
		cmd := wrapKeychainErrors(&cobra.Command{
			RunE: func(*cobra.Command, []string) error { return dup },
		})
		err := cmd.RunE(cmd, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, keychain.ErrDuplicateItem)
		assert.ErrorContains(t, err, "save 'foo'")
		assert.ErrorContains(t, err, duplicateItemHint)
	})

	t.Run("other errors pass through unchanged", func(t *testing.T) {
		plain := errors.New("boom")
		cmd := wrapKeychainErrors(&cobra.Command{
			RunE: func(*cobra.Command, []string) error { return plain },
		})
		assert.Equal(t, plain, cmd.RunE(cmd, nil))
	})

	t.Run("nil stays nil", func(t *testing.T) {
		cmd := wrapKeychainErrors(&cobra.Command{
			RunE: func(*cobra.Command, []string) error { return nil },
		})
		assert.NoError(t, cmd.RunE(cmd, nil))
	})

	t.Run("commands without hooks are left alone", func(t *testing.T) {
		cmd := wrapKeychainErrors(&cobra.Command{})
		assert.Nil(t, cmd.PreRunE)
		assert.Nil(t, cmd.RunE)
	})
}

func TestStoreCommandsHintOnLockedKeychain(t *testing.T) {
	t.Parallel()
	locked := fmt.Errorf("keychain: %w", keychain.ErrCollectionLocked)

	tests := []struct {
		name string
		cmd  *cobra.Command
		mock store.Store
		args []string
	}{
		{"get", mustGetCommand(t), teststore.NewMockStore(teststore.WithStoreGetErr(locked)), []string{"foo"}},
		{"set", SetCommand(), teststore.NewMockStore(teststore.WithStoreSaveErr(locked)), []string{"foo=bar"}},
		{"ls", ListCommand(), teststore.NewMockStore(teststore.WithStoreGetAllErr(locked)), nil},
		{"rm", mustRmCommand(t, engineOpts(t, &mockEngine{allow: true})...), teststore.NewMockStore(
			teststore.WithStore(map[store.ID]store.Secret{store.MustParseID("foo"): pass.NewPassValue([]byte("bar"))}),
			teststore.WithStoreDeleteErr(locked),
		), []string{"foo"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := execute(t, tt.cmd, tt.mock, tt.args...)
			assert.ErrorIs(t, err, keychain.ErrCollectionLocked)
			assert.ErrorContains(t, err, lockedKeychainHint)
			assert.Contains(t, out, lockedKeychainHint)
		})
	}
}
