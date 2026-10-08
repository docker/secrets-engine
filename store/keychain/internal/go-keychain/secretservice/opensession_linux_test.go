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
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	dbus "github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/require"
)

type delayedSession struct {
	ctx        context.Context
	path       dbus.ObjectPath
	reply      chan *dbus.Error
	closed     chan struct{}
	closeReply chan struct{}
}

func (s *delayedSession) Close() *dbus.Error {
	close(s.closed)
	select {
	case <-s.closeReply:
	case <-s.ctx.Done():
	}
	return nil
}

type delayedSessionService struct {
	ctx      context.Context
	conn     *dbus.Conn
	requests chan *delayedSession
	sessions []*delayedSession
	nextID   atomic.Uint32
}

func (s *delayedSessionService) OpenSession(_ string, _ dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	index := s.nextID.Add(1) - 1
	if int(index) >= len(s.sessions) {
		return dbus.Variant{}, "/", dbus.NewError("org.freedesktop.DBus.Error.Failed", []any{"unexpected session request"})
	}
	session := s.sessions[index]
	s.requests <- session
	select {
	case err := <-session.reply:
		return dbus.MakeVariant(""), session.path, err
	case <-s.ctx.Done():
		return dbus.Variant{}, "/", dbus.MakeFailedError(s.ctx.Err())
	}
}

func newDelayedSessionService(t *testing.T) (*SecretService, *delayedSessionService) {
	t.Helper()
	bus, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon is required for private-bus session tests")
	}
	cmd := exec.CommandContext(t.Context(), bus, "--session", "--nofork", "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan(), "private D-Bus daemon did not publish an address")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", scanner.Text())

	conn, err := dbus.ConnectSessionBus()
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	backend := &delayedSessionService{ctx: t.Context(), conn: conn, requests: make(chan *delayedSession, 2)}
	for i := range 2 {
		session := &delayedSession{
			ctx:        t.Context(),
			path:       dbus.ObjectPath(fmt.Sprintf("/session/s%d", i)),
			reply:      make(chan *dbus.Error, 1),
			closed:     make(chan struct{}),
			closeReply: make(chan struct{}, 1),
		}
		require.NoError(t, conn.Export(session, session.path, "org.freedesktop.Secret.Session"))
		backend.sessions = append(backend.sessions, session)
	}
	require.NoError(t, conn.Export(backend, SecretServiceObjectPath, "org.freedesktop.Secret.Service"))
	owner, err := conn.RequestName(SecretServiceInterface, dbus.NameFlagDoNotQueue)
	require.NoError(t, err)
	require.Equal(t, dbus.RequestNameReplyPrimaryOwner, owner)
	svc, err := NewService(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.conn.Close() })
	svc.SetSessionOpenTimeout(250 * time.Millisecond)
	return svc, backend
}

func receiveSessionValue[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for session test event")
		var zero T
		return zero
	}
}

func startTimedOutSession(t *testing.T, svc *SecretService, backend *delayedSessionService) *delayedSession {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		_, err := svc.OpenSession(AuthenticationInsecurePlain)
		result <- err
	}()
	request := receiveSessionValue(t, backend.requests)
	require.EqualError(t, receiveSessionValue(t, result), "timed out after 250ms")
	return request
}

func TestOpenSessionTimeoutDefersConnectionClose(t *testing.T) {
	for _, test := range []struct {
		name  string
		reply *dbus.Error
	}{
		{name: "late success"},
		{name: "late error", reply: dbus.NewError("org.freedesktop.DBus.Error.Failed", []any{"backend failed"})},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, backend := newDelayedSessionService(t)
			first := startTimedOutSession(t, svc, backend)
			second := startTimedOutSession(t, svc, backend)
			closed := make(chan error, 1)
			go func() { closed <- svc.Close() }()
			require.NoError(t, receiveSessionValue(t, closed))
			require.True(t, svc.conn.Connected(), "Close must preserve in-flight session requests")
			require.NoError(t, svc.Close())
			_, err := svc.OpenSession(AuthenticationInsecurePlain)
			require.ErrorIs(t, err, dbus.ErrClosed)

			for _, request := range []*delayedSession{first, second} {
				require.True(t, svc.conn.Connected())
				request.reply <- test.reply
				if test.reply == nil {
					receiveSessionValue(t, request.closed)
					require.True(t, svc.conn.Connected(), "late session cleanup must finish before disconnecting")
					request.closeReply <- struct{}{}
				}
			}
			receiveSessionValue(t, svc.conn.Context().Done())
			require.NoError(t, svc.Close())
		})
	}
}

func TestOpenSessionTimeoutCleansLateSessionWithoutClosingConnection(t *testing.T) {
	svc, backend := newDelayedSessionService(t)
	request := startTimedOutSession(t, svc, backend)
	request.reply <- nil
	receiveSessionValue(t, request.closed)
	request.closeReply <- struct{}{}
	require.True(t, svc.conn.Connected())

	svc.SetSessionOpenTimeout(5 * time.Second)
	result := make(chan *Session, 1)
	errors := make(chan error, 1)
	go func() {
		session, err := svc.OpenSession(AuthenticationInsecurePlain)
		result <- session
		errors <- err
	}()
	next := receiveSessionValue(t, backend.requests)
	next.reply <- nil
	session := receiveSessionValue(t, result)
	require.NoError(t, receiveSessionValue(t, errors))
	require.Equal(t, next.path, session.Path)
	next.closeReply <- struct{}{}
	svc.CloseSession(session)
	receiveSessionValue(t, next.closed)
	require.NoError(t, svc.Close())
	receiveSessionValue(t, svc.conn.Context().Done())
}

func TestOpenSessionTimeoutReleasesConnectionWhenBackendDisconnects(t *testing.T) {
	svc, backend := newDelayedSessionService(t)
	startTimedOutSession(t, svc, backend)
	require.NoError(t, svc.Close())
	require.True(t, svc.conn.Connected())
	require.NoError(t, backend.conn.Close())
	receiveSessionValue(t, svc.conn.Context().Done())
}
