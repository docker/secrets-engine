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

// This test file should only be run locally and requires a Secret Service
// keyring with a default collection created.
// It should prompt you for your keyring password twice.

//go:build linux
// +build linux

package secretservice

import (
	"testing"

	dbus "github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/require"
)

func TestKeyringPlain(t *testing.T) {
	testKeyring(t, AuthenticationInsecurePlain)
}

func TestKeyringDH(t *testing.T) {
	testKeyring(t, AuthenticationDHAES)
}

func testKeyring(t *testing.T, mode AuthenticationMode) {
	srv, err := NewService()
	require.NoError(t, err)
	session, err := srv.OpenSession(mode)
	require.NoError(t, err)
	defer srv.CloseSession(session)

	collection := DefaultCollection

	items, err := srv.SearchCollection(collection, map[string]string{"foo": "bar"})
	require.NoError(t, err)
	require.Equal(t, len(items), 0)

	secret, err := session.NewSecret([]byte("secret"))
	require.NoError(t, err)

	err = srv.Unlock([]dbus.ObjectPath{collection})
	require.NoError(t, err)

	_, err = srv.CreateItem(collection, NewSecretProperties("testlabel", map[string]string{"foo": "bar"}), secret, ReplaceBehaviorReplace)
	require.NoError(t, err)

	items, err = srv.SearchCollection(collection, map[string]string{"foo": "bar"})
	require.NoError(t, err)
	require.Equal(t, len(items), 1)
	gotItem := items[0]
	secretPlaintext, err := srv.GetSecret(gotItem, *session)
	require.NoError(t, err)
	require.Equal(t, secretPlaintext, []byte("secret"))

	err = srv.DeleteItem(gotItem)
	require.NoError(t, err)

	err = srv.LockItems([]dbus.ObjectPath{collection})
	require.NoError(t, err)
}

func TestGetAll(t *testing.T) {
	srv, err := NewService()
	require.NoError(t, err)
	session, err := srv.OpenSession(AuthenticationDHAES)
	require.NoError(t, err)
	defer srv.CloseSession(session)

	collection := DefaultCollection

	secret, err := session.NewSecret([]byte("secret"))
	require.NoError(t, err)

	err = srv.Unlock([]dbus.ObjectPath{collection})
	require.NoError(t, err)

	item, err := srv.CreateItem(collection, NewSecretProperties("testlabel", map[string]string{"username": "testuser"}), secret, ReplaceBehaviorReplace)
	require.NoError(t, err)

	attrs, err := srv.GetAttributes(item)
	require.NoError(t, err)
	require.Equal(t, attrs["username"], "testuser")

	err = srv.DeleteItem(item)
	require.NoError(t, err)
}
