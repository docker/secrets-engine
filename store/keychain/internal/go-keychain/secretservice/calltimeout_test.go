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

package secretservice

import (
	"context"
	"testing"
	"time"

	dbus "github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/require"
)

const (
	propertiesInterface = "org.freedesktop.DBus.Properties"
	loginCollectionPath = dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
)

type blockedCall struct {
	entered chan struct{}
	release chan struct{}
}

func newBlockedCall(t *testing.T) *blockedCall {
	t.Helper()
	blocked := &blockedCall{entered: make(chan struct{}, 1), release: make(chan struct{})}
	t.Cleanup(func() { close(blocked.release) })
	return blocked
}

func (b *blockedCall) block() {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
}

func (b *blockedCall) Get(string, string) (dbus.Variant, *dbus.Error) {
	b.block()
	return dbus.MakeVariant([]dbus.ObjectPath{loginCollectionPath}), nil
}

func (b *blockedCall) ReadAlias(string) (dbus.ObjectPath, *dbus.Error) {
	b.block()
	return loginCollectionPath, nil
}

func (b *blockedCall) Set(string, string, dbus.Variant) *dbus.Error {
	b.block()
	return nil
}

func (b *blockedCall) SearchItems(map[string]string) *dbus.Error {
	b.block()
	return nil
}

func (b *blockedCall) CreateItem(map[string]dbus.Variant, Secret, bool) *dbus.Error {
	b.block()
	return nil
}

func (b *blockedCall) Delete() *dbus.Error {
	b.block()
	return nil
}

func (b *blockedCall) GetSecret(dbus.ObjectPath) *dbus.Error {
	b.block()
	return nil
}

func (b *blockedCall) SetSecret(Secret) *dbus.Error {
	b.block()
	return nil
}

func (b *blockedCall) Unlock([]dbus.ObjectPath) *dbus.Error {
	b.block()
	return nil
}

func (b *blockedCall) Lock([]dbus.ObjectPath) *dbus.Error {
	b.block()
	return nil
}

func (b *blockedCall) Close() *dbus.Error {
	b.block()
	return nil
}

func (b *blockedCall) Prompt(string) *dbus.Error {
	b.block()
	return nil
}

func TestCallContextDeadline(t *testing.T) {
	t.Run("falls back to the default when the caller sets none", func(t *testing.T) {
		before := time.Now()
		ctx, cancel := callContext(context.Background())
		defer cancel()

		deadline, ok := ctx.Deadline()
		require.True(t, ok, "a caller without a deadline must still be bounded")
		require.WithinDuration(t, before.Add(defaultCallTimeout), deadline, time.Second)
	})

	t.Run("keeps a caller deadline longer than the default", func(t *testing.T) {
		callerDeadline := time.Now().Add(2 * defaultCallTimeout)
		parent, cancelParent := context.WithDeadline(context.Background(), callerDeadline)
		defer cancelParent()
		ctx, cancel := callContext(parent)
		defer cancel()

		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.WithinDuration(t, callerDeadline, deadline, time.Millisecond,
			"a caller-supplied deadline must not be capped by the default")
	})

	t.Run("keeps a caller deadline shorter than the default", func(t *testing.T) {
		callerDeadline := time.Now().Add(50 * time.Millisecond)
		parent, cancelParent := context.WithDeadline(context.Background(), callerDeadline)
		defer cancelParent()
		ctx, cancel := callContext(parent)
		defer cancel()

		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.WithinDuration(t, callerDeadline, deadline, time.Millisecond)
	})
}

func TestCollectionsCallerDeadline(t *testing.T) {
	svc, backend := newDelayedSessionService(t)
	blocked := newBlockedCall(t)
	require.NoError(t, backend.conn.Export(blocked, SecretServiceObjectPath, propertiesInterface))

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := svc.Collections(ctx)
		result <- err
	}()

	receiveSessionValue(t, blocked.entered)
	require.ErrorIs(t, receiveSessionValue(t, result), context.DeadlineExceeded)
	require.True(t, svc.conn.Connected(), "a timed-out property read must not disconnect the service")
}

func TestIsLockedCallerDeadline(t *testing.T) {
	svc, backend := newDelayedSessionService(t)
	blocked := newBlockedCall(t)
	require.NoError(t, backend.conn.Export(blocked, loginCollectionPath, propertiesInterface))

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := svc.IsLocked(ctx, loginCollectionPath)
		result <- err
	}()

	receiveSessionValue(t, blocked.entered)
	require.ErrorIs(t, receiveSessionValue(t, result), context.DeadlineExceeded)
}

func TestReadAliasCallerDeadline(t *testing.T) {
	svc, backend := newDelayedSessionService(t)
	blocked := newBlockedCall(t)
	require.NoError(t, backend.conn.Export(blocked, SecretServiceObjectPath, secretServiceInterfaceName))

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := svc.ReadAlias(ctx, "default")
		result <- err
	}()

	receiveSessionValue(t, blocked.entered)
	require.ErrorIs(t, receiveSessionValue(t, result), context.DeadlineExceeded)
	require.True(t, svc.conn.Connected())
}

func TestItemCallsCallerDeadline(t *testing.T) {
	const (
		itemPath    = dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
		sessionPath = dbus.ObjectPath("/session/blocked")
		promptPath  = dbus.ObjectPath("/prompt/blocked")
	)
	secret := Secret{Session: sessionPath, Value: []byte("value"), ContentType: "text/plain"}
	attributes := Attributes{"foo": "bar"}

	for _, test := range []struct {
		name  string
		path  dbus.ObjectPath
		iface string
		call  func(context.Context, *SecretService) error
	}{
		{
			name: "SearchCollection", path: loginCollectionPath, iface: secretCollectionInterfaceName,
			call: func(ctx context.Context, svc *SecretService) error {
				_, err := svc.SearchCollection(ctx, loginCollectionPath, attributes)
				return err
			},
		},
		{
			name: "CreateItem", path: loginCollectionPath, iface: secretCollectionInterfaceName,
			call: func(ctx context.Context, svc *SecretService) error {
				_, err := svc.CreateItem(ctx, loginCollectionPath, NewSecretProperties("label", attributes), secret, ReplaceBehaviorReplace)
				return err
			},
		},
		{
			name: "DeleteItem", path: itemPath, iface: secretItemInterfaceName,
			call: func(ctx context.Context, svc *SecretService) error {
				return svc.DeleteItem(ctx, itemPath)
			},
		},
		{
			name: "GetAttributes", path: itemPath, iface: propertiesInterface,
			call: func(ctx context.Context, svc *SecretService) error {
				_, err := svc.GetAttributes(ctx, itemPath)
				return err
			},
		},
		{
			name: "GetSecret", path: itemPath, iface: secretItemInterfaceName,
			call: func(ctx context.Context, svc *SecretService) error {
				_, err := svc.GetSecret(ctx, itemPath, Session{Mode: AuthenticationInsecurePlain, Path: sessionPath})
				return err
			},
		},
		{
			name: "SetItemSecret", path: itemPath, iface: secretItemInterfaceName,
			call: func(ctx context.Context, svc *SecretService) error {
				return svc.SetItemSecret(ctx, itemPath, secret)
			},
		},
		{
			name: "SetItemAttributes", path: itemPath, iface: propertiesInterface,
			call: func(ctx context.Context, svc *SecretService) error {
				return svc.SetItemAttributes(ctx, itemPath, attributes)
			},
		},
		{
			name: "SetItemLabel", path: itemPath, iface: propertiesInterface,
			call: func(ctx context.Context, svc *SecretService) error {
				return svc.SetItemLabel(ctx, itemPath, "label")
			},
		},
		{
			name: "Unlock", path: SecretServiceObjectPath, iface: secretServiceInterfaceName,
			call: func(ctx context.Context, svc *SecretService) error {
				return svc.Unlock(ctx, []dbus.ObjectPath{loginCollectionPath})
			},
		},
		{
			name: "LockItems", path: SecretServiceObjectPath, iface: secretServiceInterfaceName,
			call: func(ctx context.Context, svc *SecretService) error {
				return svc.LockItems(ctx, []dbus.ObjectPath{loginCollectionPath})
			},
		},
		{
			name: "PromptAndWait", path: promptPath, iface: "org.freedesktop.Secret.Prompt",
			call: func(ctx context.Context, svc *SecretService) error {
				_, err := svc.PromptAndWait(ctx, promptPath)
				return err
			},
		},
		{
			name: "CloseSession", path: sessionPath, iface: "org.freedesktop.Secret.Session",
			call: func(ctx context.Context, svc *SecretService) error {
				svc.CloseSession(ctx, &Session{Path: sessionPath})
				return ctx.Err()
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, backend := newDelayedSessionService(t)
			blocked := newBlockedCall(t)
			require.NoError(t, backend.conn.Export(blocked, test.path, test.iface))

			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- test.call(ctx, svc) }()

			receiveSessionValue(t, blocked.entered)
			require.ErrorIs(t, receiveSessionValue(t, result), context.DeadlineExceeded)
			require.True(t, svc.conn.Connected())
		})
	}
}
