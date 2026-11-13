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
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	healthv1 "github.com/docker/secrets-engine/client/api/health/v1"
)

func rawVersionEngine(t *testing.T, h http.HandlerFunc) Client {
	t.Helper()
	socketPath := randomShortSocketName()
	muxServer(t, socketPath, []handler{wrapHandler(getVersionProcedure, h)})
	c, err := New(WithSocketPath(socketPath))
	require.NoError(t, err)
	return c
}

func respond(status int, contentType, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func Test_call(t *testing.T) {
	t.Parallel()
	t.Run("sends a Connect unary request", func(t *testing.T) {
		var (
			method string
			header http.Header
		)
		c := rawVersionEngine(t, func(w http.ResponseWriter, r *http.Request) {
			method, header = r.Method, r.Header.Clone()
			body, err := proto.Marshal(healthv1.GetVersionResponse_builder{Version: proto.String("v1.2.3")}.Build())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/proto")
			_, _ = w.Write(body)
		})
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()

		dv, err := c.Version(ctx)
		require.NoError(t, err)
		assert.Equal(t, "v1.2.3", dv.Version.String())
		assert.Equal(t, http.MethodPost, method)
		assert.Equal(t, "application/proto", header.Get("Content-Type"))
		assert.Equal(t, "1", header.Get("Connect-Protocol-Version"))
		timeout, err := strconv.Atoi(header.Get("Connect-Timeout-Ms"))
		require.NoError(t, err, "the context deadline travels as Connect-Timeout-Ms")
		assert.Positive(t, timeout)
		assert.LessOrEqual(t, timeout, int(time.Minute.Milliseconds()))
	})
	t.Run("sends no timeout without a deadline", func(t *testing.T) {
		var header http.Header
		c := rawVersionEngine(t, func(w http.ResponseWriter, r *http.Request) {
			header = r.Header.Clone()
			w.WriteHeader(http.StatusNotFound)
		})
		_, err := c.Version(t.Context())
		require.Error(t, err)
		assert.Empty(t, header.Values("Connect-Timeout-Ms"))
	})

	t.Run("reports a dial failure without the request URL", func(t *testing.T) {
		c, err := New(WithSocketPath(randomShortSocketName()))
		require.NoError(t, err)
		_, err = c.Version(t.Context())
		require.ErrorIs(t, err, ErrSecretsEngineNotRunning)
		assert.NotContains(t, err.Error(), baseURL)
	})
	t.Run("keeps context errors matchable", func(t *testing.T) {
		c := rawVersionEngine(t, func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		})
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		_, err := c.Version(ctx)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	errorTests := []struct {
		name    string
		handler http.HandlerFunc
		want    RPCError
	}{
		{
			name:    "Connect error",
			handler: respond(http.StatusNotFound, "application/json", `{"code":"not_found","message":"no such plugin"}`),
			want:    RPCError{Code: CodeNotFound, Message: "no such plugin"},
		},
		{
			name:    "Connect error without a message",
			handler: respond(http.StatusInternalServerError, "application/json", `{"code":"internal"}`),
			want:    RPCError{Code: CodeInternal},
		},
		{
			name:    "JSON error without a code takes the code from the status",
			handler: respond(http.StatusServiceUnavailable, "application/json; charset=utf-8", `{"message":"starting"}`),
			want:    RPCError{Code: CodeUnavailable, Message: "starting"},
		},
		{
			name:    "malformed JSON error takes code and message from the status",
			handler: respond(http.StatusTooManyRequests, "application/json", `{`),
			want:    RPCError{Code: CodeUnavailable, Message: "429 Too Many Requests"},
		},
		{
			name:    "procedure the engine does not serve",
			handler: http.NotFound,
			want:    RPCError{Code: CodeUnimplemented, Message: "404 Not Found"},
		},
		{
			name:    "bad request",
			handler: respond(http.StatusBadRequest, "", ""),
			want:    RPCError{Code: CodeInternal, Message: "400 Bad Request"},
		},
		{
			name:    "unauthorized",
			handler: respond(http.StatusUnauthorized, "", ""),
			want:    RPCError{Code: CodeUnauthenticated, Message: "401 Unauthorized"},
		},
		{
			name:    "forbidden",
			handler: respond(http.StatusForbidden, "", ""),
			want:    RPCError{Code: CodePermissionDenied, Message: "403 Forbidden"},
		},
		{
			name:    "other status",
			handler: respond(http.StatusTeapot, "text/plain", "short and stout"),
			want:    RPCError{Code: CodeUnknown, Message: "418 I'm a teapot"},
		},
	}
	for _, tc := range errorTests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rawVersionEngine(t, tc.handler).Version(t.Context())
			assert.Equal(t, &tc.want, err)
		})
	}

	t.Run("rejects a response that is not protobuf", func(t *testing.T) {
		_, err := rawVersionEngine(t, respond(http.StatusOK, "text/html", "<html></html>")).Version(t.Context())
		require.ErrorContains(t, err, `invalid content-type "text/html"`)
		_, ok := errors.AsType[*RPCError](err)
		assert.False(t, ok, "the engine reported no error")
	})
	t.Run("rejects a malformed message", func(t *testing.T) {
		_, err := rawVersionEngine(t, respond(http.StatusOK, "application/proto", "\xff")).Version(t.Context())
		require.ErrorContains(t, err, "unmarshal response")
	})
}
