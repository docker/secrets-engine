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
	"io"
	"math/big"
	"net"
	"strings"
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
	aesKey     chan []byte
}

func (s *delayedSession) Close() *dbus.Error {
	close(s.closed)
	select {
	case <-s.closeReply:
	case <-s.ctx.Done():
	}
	return nil
}

func (s *delayedSession) negotiate(algorithm string, input dbus.Variant) (dbus.Variant, *dbus.Error) {
	if AuthenticationMode(algorithm) == AuthenticationInsecurePlain {
		return dbus.MakeVariant(""), nil
	}
	theirPublic, ok := input.Value().([]byte)
	if !ok {
		return dbus.Variant{}, dbus.NewError("org.freedesktop.DBus.Error.Failed", []any{"expected a byteslice public key"})
	}
	group := rfc2409SecondOakleyGroup()
	private, public, err := group.NewKeypair()
	if err != nil {
		return dbus.Variant{}, dbus.MakeFailedError(err)
	}
	aesKey, err := group.keygenHKDFSHA256AES128(new(big.Int).SetBytes(theirPublic), private)
	if err != nil {
		return dbus.Variant{}, dbus.MakeFailedError(err)
	}
	s.aesKey <- aesKey
	return dbus.MakeVariant(group.encode(public)), nil
}

type delayedSessionService struct {
	ctx      context.Context
	conn     *dbus.Conn
	requests chan *delayedSession
	sessions []*delayedSession
	nextID   atomic.Uint32
}

func (s *delayedSessionService) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	index := s.nextID.Add(1) - 1
	if int(index) >= len(s.sessions) {
		return dbus.Variant{}, "/", dbus.NewError("org.freedesktop.DBus.Error.Failed", []any{"unexpected session request"})
	}
	session := s.sessions[index]
	s.requests <- session
	select {
	case err := <-session.reply:
		if err != nil {
			return dbus.Variant{}, "/", err
		}
		output, negotiateErr := session.negotiate(algorithm, input)
		if negotiateErr != nil {
			return dbus.Variant{}, "/", negotiateErr
		}
		return output, session.path, nil
	case <-s.ctx.Done():
		return dbus.Variant{}, "/", dbus.MakeFailedError(s.ctx.Err())
	}
}

func answerAuth(rw io.ReadWriter) (*bufio.Reader, error) {
	in := bufio.NewReader(rw)
	if _, err := in.ReadByte(); err != nil {
		return nil, err
	}
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			return nil, err
		}
		var reply string
		switch line = strings.TrimSuffix(line, "\r\n"); {
		case line == "AUTH":
			reply = "REJECTED ANONYMOUS"
		case strings.HasPrefix(line, "AUTH ANONYMOUS"):
			reply = "OK 0123456789abcdef0123456789abcdef"
		case line == "BEGIN":
			return in, nil
		default:
			reply = "ERROR"
		}
		if _, err := io.WriteString(rw, reply+"\r\n"); err != nil {
			return nil, err
		}
	}
}

func newPeerConns(t *testing.T) (client, service *dbus.Conn) {
	t.Helper()
	clientEnd, clientRelay := net.Pipe()
	serviceEnd, serviceRelay := net.Pipe()
	t.Cleanup(func() {
		_ = clientRelay.Close()
		_ = serviceRelay.Close()
	})
	client, err := dbus.NewConn(clientEnd)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	service, err = dbus.NewConn(serviceEnd)
	require.NoError(t, err)
	t.Cleanup(func() { _ = service.Close() })

	var fromClient, fromService *bufio.Reader
	handshakes := make(chan error, 4)
	go func() {
		var err error
		fromClient, err = answerAuth(clientRelay)
		handshakes <- err
	}()
	go func() {
		var err error
		fromService, err = answerAuth(serviceRelay)
		handshakes <- err
	}()
	go func() { handshakes <- client.Auth([]dbus.Auth{dbus.AuthAnonymous()}) }()
	go func() { handshakes <- service.Auth([]dbus.Auth{dbus.AuthAnonymous()}) }()
	for range 4 {
		require.NoError(t, receiveSessionValue(t, handshakes))
	}

	go func() { _, _ = io.Copy(serviceRelay, fromClient) }()
	go func() {
		_, _ = io.Copy(clientRelay, fromService)
		_ = clientRelay.Close()
	}()
	return client, service
}

func newDelayedSessionService(t *testing.T) (*SecretService, *delayedSessionService) {
	t.Helper()
	client, conn := newPeerConns(t)
	backend := &delayedSessionService{ctx: t.Context(), conn: conn, requests: make(chan *delayedSession, 2)}
	for i := range 2 {
		session := &delayedSession{
			ctx:        t.Context(),
			path:       dbus.ObjectPath(fmt.Sprintf("/session/s%d", i)),
			reply:      make(chan *dbus.Error, 1),
			closed:     make(chan struct{}),
			closeReply: make(chan struct{}, 1),
			aesKey:     make(chan []byte, 1),
		}
		require.NoError(t, conn.Export(session, session.path, "org.freedesktop.Secret.Session"))
		backend.sessions = append(backend.sessions, session)
	}
	require.NoError(t, conn.Export(backend, SecretServiceObjectPath, "org.freedesktop.Secret.Service"))
	svc := &SecretService{conn: client}
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

type openResult struct {
	session *Session
	err     error
}

func openSessionAsync(ctx context.Context, svc *SecretService) <-chan openResult {
	result := make(chan openResult, 1)
	go func() {
		session, err := svc.OpenSession(ctx, AuthenticationDHAES)
		result <- openResult{session: session, err: err}
	}()
	return result
}

func TestOpenSessionNegotiatesDHAES(t *testing.T) {
	svc, backend := newDelayedSessionService(t)

	result := openSessionAsync(t.Context(), svc)
	request := receiveSessionValue(t, backend.requests)
	request.reply <- nil

	opened := receiveSessionValue(t, result)
	require.NoError(t, opened.err)
	require.Equal(t, request.path, opened.session.Path)
	require.Equal(t, receiveSessionValue(t, request.aesKey), opened.session.AESKey)

	request.closeReply <- struct{}{}
	svc.CloseSession(opened.session)
	receiveSessionValue(t, request.closed)
	require.NoError(t, svc.Close())
	receiveSessionValue(t, svc.conn.Context().Done())
}

func TestOpenSessionTimeout(t *testing.T) {
	for _, test := range []struct {
		name  string
		reply *dbus.Error
	}{
		{name: "late success"},
		{name: "late error", reply: dbus.NewError("org.freedesktop.DBus.Error.Failed", []any{"backend failed"})},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, backend := newDelayedSessionService(t)

			timeoutCtx, cancelTimeout := context.WithTimeout(t.Context(), 250*time.Millisecond)
			defer cancelTimeout()
			result := openSessionAsync(timeoutCtx, svc)
			late := receiveSessionValue(t, backend.requests)
			timedOut := receiveSessionValue(t, result)
			require.ErrorIs(t, timedOut.err, context.DeadlineExceeded)
			require.Nil(t, timedOut.session)
			require.True(t, svc.conn.Connected(), "a timed-out open must not disconnect the service")

			late.reply <- test.reply

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			result = openSessionAsync(ctx, svc)
			next := receiveSessionValue(t, backend.requests)
			next.reply <- nil
			opened := receiveSessionValue(t, result)
			require.NoError(t, opened.err, "a late reply must not be delivered to the next call")
			require.Equal(t, next.path, opened.session.Path)
			require.Equal(t, receiveSessionValue(t, next.aesKey), opened.session.AESKey)

			require.NoError(t, svc.Close())
			receiveSessionValue(t, svc.conn.Context().Done())
		})
	}
}

func TestOpenSessionTimeoutThenCloseDisconnects(t *testing.T) {
	svc, backend := newDelayedSessionService(t)

	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	result := openSessionAsync(ctx, svc)
	receiveSessionValue(t, backend.requests)
	require.ErrorIs(t, receiveSessionValue(t, result).err, context.DeadlineExceeded)

	require.NoError(t, svc.Close())
	receiveSessionValue(t, svc.conn.Context().Done())
	require.NoError(t, svc.Close())
}

func TestOpenSessionCallerCancel(t *testing.T) {
	svc, backend := newDelayedSessionService(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := openSessionAsync(ctx, svc)
	receiveSessionValue(t, backend.requests)
	cancel()

	cancelled := receiveSessionValue(t, result)
	require.ErrorIs(t, cancelled.err, context.Canceled)
	require.Nil(t, cancelled.session)
	require.True(t, svc.conn.Connected())
}

func TestOpenSessionCancelledContext(t *testing.T) {
	for _, mode := range []AuthenticationMode{AuthenticationInsecurePlain, AuthenticationDHAES} {
		t.Run(string(mode), func(t *testing.T) {
			svc, backend := newDelayedSessionService(t)

			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			session, err := svc.OpenSession(ctx, mode)
			require.ErrorIs(t, err, context.Canceled)
			require.Nil(t, session)
			require.Zero(t, backend.nextID.Load(), "a cancelled context must not reach the backend")
		})
	}
}
