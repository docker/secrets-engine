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

package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client/dockerhub"
	"github.com/docker/secrets-engine/client/trace"
	"github.com/docker/secrets-engine/x/api/resolver"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

type spanKey struct{}

type event struct {
	kind   string // "start" or "done"
	op     Operation
	span   any   // span value seen in ctx
	err    error // done only
	kindOf string
}

// recorder records hook calls. Start stores a unique span ID in the context,
// nesting under the parent span when there is one.
type recorder struct {
	mu     sync.Mutex
	events []event
	next   int
}

func (r *recorder) hooks() Hooks {
	return Hooks{
		Start: func(ctx context.Context, op Operation) context.Context {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.next++
			span := fmt.Sprintf("%v/%d", ctx.Value(spanKey{}), r.next)
			r.events = append(r.events, event{kind: "start", op: op, span: span})
			return context.WithValue(ctx, spanKey{}, span)
		},
		Done: func(ctx context.Context, op Operation, err error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.events = append(r.events, event{kind: "done", op: op, span: ctx.Value(spanKey{}), err: err, kindOf: ErrorKind(err)})
		},
	}
}

func (r *recorder) snapshot() []event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]event(nil), r.events...)
}

// assertPaired checks that every Start has exactly one matching Done, nested
// like a stack, and that Done sees the context Start returned.
func assertPaired(t *testing.T, events []event) {
	t.Helper()
	var stack []event
	for _, e := range events {
		switch e.kind {
		case "start":
			stack = append(stack, e)
		case "done":
			require.NotEmpty(t, stack, "done without start: %+v", e)
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			assert.Equal(t, top.op, e.op)
			assert.Equal(t, top.span, e.span, "Done must receive the ctx returned by Start")
		}
	}
	assert.Empty(t, stack, "start without done")
}

// spyTransport records the span value in each outgoing request's context.
type spyTransport struct {
	next  http.RoundTripper
	mu    sync.Mutex
	spans []any
}

func (s *spyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.spans = append(s.spans, req.Context().Value(spanKey{}))
	s.mu.Unlock()
	return s.next.RoundTrip(req)
}

func (s *spyTransport) wrap(next http.RoundTripper) http.RoundTripper {
	s.next = next
	return s
}

func mockResolverEngine(t *testing.T, store map[string]string) string {
	t.Helper()
	resolved := make(map[secrets.ID]string, len(store))
	for id, v := range store {
		resolved[secrets.MustParseID(id)] = v
	}
	socketPath := testhelper.RandomShortSocketName()
	muxServer(t, socketPath, []handler{
		wrapHandler(resolverv1connect.NewResolverServiceHandler(resolver.NewResolverHandler(testhelper.MockResolver{Store: resolved}))),
	})
	return socketPath
}

func TestHooks_StartContextReachesTransport(t *testing.T) {
	socket := mockResolverEngine(t, map[string]string{"acme/token": "s3cr3t"})
	rec := &recorder{}
	spy := &spyTransport{}
	c, err := New(WithSocketPath(socket), WithHooks(rec.hooks()), WithTransport(spy.wrap))
	require.NoError(t, err)

	_, err = c.GetSecrets(t.Context(), MustParsePattern("acme/token"))
	require.NoError(t, err)

	events := rec.snapshot()
	require.Len(t, events, 2)
	assertPaired(t, events)
	assert.Equal(t, Operation{Name: trace.OpResolverGetSecrets}, events[0].op)
	assert.NoError(t, events[1].err)
	assert.Equal(t, []any{events[0].span}, spy.spans, "the RPC must use the ctx returned by Start")
}

func TestHooks_EveryClientOperation(t *testing.T) {
	rec := &recorder{}
	c, err := New(WithSocketPath(testhelper.RandomShortSocketName()), WithHooks(rec.hooks()))
	require.NoError(t, err)
	m, err := PluginManagementFromClient(c)
	require.NoError(t, err)

	ctx := t.Context()
	_, _ = c.GetSecrets(ctx, MustParsePattern("**"))
	_, _ = c.Authorize(ctx, MustParsePattern("**"))
	_, _ = c.Version(ctx)
	_, _ = m.ListPlugins(ctx)
	_ = m.EnablePlugin(ctx, "my-plugin")
	_ = m.DisablePlugin(ctx, "my-plugin")

	events := rec.snapshot()
	assertPaired(t, events)
	var names []string
	for _, e := range events {
		if e.kind == "done" {
			names = append(names, e.op.Name)
			assert.Equal(t, ErrorKindEngineUnavailable, e.kindOf, e.op.Name)
			assert.Empty(t, e.op.Realm)
		}
	}
	assert.Equal(t, []string{
		trace.OpResolverGetSecrets,
		trace.OpAuthorizerAuthorize,
		trace.OpVersion,
		trace.OpPluginsList,
		trace.OpPluginsEnable,
		trace.OpPluginsDisable,
	}, names)
}

func TestHooks_HubAuthInheritsHooks(t *testing.T) {
	const token = "token-alice-very-secret"
	store := map[string]string{
		"docker/auth/hub/alice":                    `{"access_token":"` + token + `","claims":{"username":"alice","email":"alice@example.com"}}`,
		"docker/auth/metadata/hub/alice":           `{"user_id":"docker/auth/hub/alice","username":"alice","email":"alice@example.com"}`,
		"docker/auth/metadata/hub/default":         `{"user_id":"docker/auth/hub/alice","username":"alice","email":"alice@example.com"}`,
		"docker/auth/hub-staging/bob":              `{"access_token":"` + token + `"}`,
		"docker/auth/metadata/hub-staging/bob":     `{"user_id":"docker/auth/hub-staging/bob","username":"bob"}`,
		"docker/auth/metadata/hub-staging/default": `{"user_id":"docker/auth/hub-staging/bob","username":"bob"}`,
	}
	socket := mockResolverEngine(t, store)
	rec := &recorder{}
	spy := &spyTransport{}
	c, err := New(WithSocketPath(socket), WithHooks(rec.hooks()), WithTransport(spy.wrap))
	require.NoError(t, err)

	session, err := c.HubAuth().GetDefaultSession(t.Context())
	require.NoError(t, err)
	require.Equal(t, token, session.AccessToken)

	events := rec.snapshot()
	assertPaired(t, events)
	require.Len(t, events, 6)
	hubOp := Operation{Name: trace.OpDockerHubGetDefaultSession, Realm: trace.RealmDockerHub}
	assert.Equal(t, hubOp, events[0].op)
	assert.Equal(t, Operation{Name: trace.OpResolverGetSecrets}, events[1].op)
	assert.True(t, strings.HasPrefix(events[1].span.(string), events[0].span.(string)+"/"),
		"resolver call must nest under the dockerhub call: %v", events)
	assert.Equal(t, hubOp, events[5].op)
	require.Len(t, spy.spans, 2)
	for i, s := range spy.spans {
		assert.True(t, strings.HasPrefix(s.(string), events[0].span.(string)+"/"), "request %d", i)
	}

	t.Run("staging realm", func(t *testing.T) {
		rec.events = nil
		_, err := c.HubAuth(dockerhub.Staging()).GetSession(t.Context(), "bob")
		require.NoError(t, err)
		events := rec.snapshot()
		assertPaired(t, events)
		assert.Equal(t, Operation{Name: trace.OpDockerHubGetSession, Realm: trace.RealmDockerHubStaging}, events[0].op)
	})

	t.Run("dockerhub.WithHooks overrides client hooks", func(t *testing.T) {
		rec.events = nil
		other := &recorder{}
		_, err := c.HubAuth(dockerhub.WithHooks(other.hooks())).GetDefaultProfile(t.Context())
		require.NoError(t, err)
		require.Len(t, other.snapshot(), 2)
		assert.Equal(t, trace.OpDockerHubGetDefaultProfile, other.snapshot()[0].op.Name)
		// The client's own resolver call still reports to the client hooks.
		require.Len(t, rec.snapshot(), 2)
		assert.Equal(t, trace.OpResolverGetSecrets, rec.snapshot()[0].op.Name)
	})
}

func TestHooks_NoSecretData(t *testing.T) {
	const token = "tok-9f8e7d6c5b4a"
	store := map[string]string{
		"docker/auth/hub/alice":            `{"access_token":"` + token + `","claims":{"username":"alice","email":"alice@example.com"}}`,
		"docker/auth/metadata/hub/default": `{"user_id":"docker/auth/hub/alice","username":"alice","email":"alice@example.com"}`,
		"docker/auth/metadata/hub/alice":   `{"user_id":"docker/auth/hub/alice","username":"alice","email":"alice@example.com"}`,
		"docker/auth/hub/broken":           `{"access_token":""}`,
	}
	socket := mockResolverEngine(t, store)
	rec := &recorder{}
	c, err := New(WithSocketPath(socket), WithHooks(rec.hooks()))
	require.NoError(t, err)
	hub := c.HubAuth()

	ctx := t.Context()
	_, err = hub.GetDefaultSession(ctx)
	require.NoError(t, err)
	_, err = hub.GetSession(ctx, "alice")
	require.NoError(t, err)
	_, err = hub.GetSession(ctx, "broken")
	require.Error(t, err)
	_, err = hub.GetSession(ctx, "nobody")
	require.ErrorIs(t, err, dockerhub.ErrNoSession)
	_, err = hub.ListProfiles(ctx)
	require.NoError(t, err)
	_, err = c.GetSecrets(ctx, MustParsePattern("docker/auth/hub/alice"))
	require.NoError(t, err)

	events := rec.snapshot()
	assertPaired(t, events)
	for _, e := range events {
		seen := fmt.Sprintf("%+v %v %v", e.op, e.span, e.err)
		for _, secret := range []string{token, "alice@example.com"} {
			assert.NotContains(t, seen, secret)
		}
		// Usernames and patterns stay out of the operation.
		assert.NotContains(t, fmt.Sprintf("%+v", e.op), "alice")
		assert.NotContains(t, fmt.Sprintf("%+v", e.op), "docker/auth")
	}
}

func TestHooks_ZeroAndPartialHooksAreSafe(t *testing.T) {
	socket := mockResolverEngine(t, map[string]string{"acme/token": "v"})
	for name, h := range map[string]Hooks{
		"zero":            {},
		"start only, nil": {Start: func(context.Context, Operation) context.Context { return nil }},
		"done only":       {Done: func(context.Context, Operation, error) {}},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New(WithSocketPath(socket), WithHooks(h))
			require.NoError(t, err)
			got, err := c.GetSecrets(t.Context(), MustParsePattern("acme/token"))
			require.NoError(t, err)
			require.Len(t, got, 1)
			_, err = c.HubAuth().GetDefaultSession(t.Context())
			require.ErrorIs(t, err, dockerhub.ErrNoSession)
		})
	}
}

func TestWithTransport(t *testing.T) {
	_, err := New(WithTransport(nil))
	require.Error(t, err)
	_, err = New(WithTransport(func(http.RoundTripper) http.RoundTripper { return nil }))
	require.Error(t, err)

	socket := mockResolverEngine(t, map[string]string{"acme/token": "v"})
	var order []string
	layer := func(name string) func(http.RoundTripper) http.RoundTripper {
		return func(next http.RoundTripper) http.RoundTripper {
			return roundTripFunc(func(req *http.Request) (*http.Response, error) {
				order = append(order, name)
				return next.RoundTrip(req)
			})
		}
	}
	c, err := New(WithSocketPath(socket), WithTransport(layer("inner")), WithTransport(layer("outer")))
	require.NoError(t, err)
	_, err = c.GetSecrets(t.Context(), MustParsePattern("acme/token"))
	require.NoError(t, err)
	assert.Equal(t, []string{"outer", "inner"}, order)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestHooks_TimeoutKind(t *testing.T) {
	socketPath := testhelper.RandomShortSocketName()
	muxServer(t, socketPath, []handler{wrapHandler("/", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))})
	rec := &recorder{}
	c, err := New(WithSocketPath(socketPath), WithTimeout(50*time.Millisecond), WithHooks(rec.hooks()))
	require.NoError(t, err)
	_, err = c.GetSecrets(t.Context(), MustParsePattern("**"))
	require.Error(t, err)
	assert.Equal(t, ErrorKindTimeout, ErrorKind(err))
	events := rec.snapshot()
	require.Len(t, events, 2)
	assert.Equal(t, ErrorKindTimeout, events[1].kindOf)
}
