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

package rpc_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	healthv1 "github.com/docker/secrets-engine/client/api/health/v1"
	"github.com/docker/secrets-engine/client/rpc"
)

const procedure = "/health.v1.VersionService/GetVersion"

type doFunc func(*http.Request) (*http.Response, error)

func (f doFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func serve(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// blockingServer serves a handler that calls onRequest and then blocks until the test ends.
func blockingServer(t *testing.T, onRequest func(http.ResponseWriter)) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	server := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		onRequest(w)
		<-release
	})
	t.Cleanup(func() { close(release) })
	return server
}

func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	return blockingServer(t, func(http.ResponseWriter) {})
}

func stallingServer(t *testing.T, status int, contentType string) *httptest.Server {
	t.Helper()
	return blockingServer(t, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_ = http.NewResponseController(w).Flush()
	})
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

func call(ctx context.Context, client *rpc.Client) (*healthv1.GetVersionResponse, error) {
	res := &healthv1.GetVersionResponse{}
	err := client.Call(ctx, procedure, &healthv1.GetVersionRequest{}, res)
	return res, err
}

func callServer(ctx context.Context, server *httptest.Server) (*healthv1.GetVersionResponse, error) {
	return call(ctx, rpc.NewClient(server.Client(), server.URL))
}

func TestCall(t *testing.T) {
	t.Parallel()
	t.Run("sends a Connect unary request", func(t *testing.T) {
		var (
			method string
			path   string
			header http.Header
		)
		server := serve(t, func(w http.ResponseWriter, r *http.Request) {
			method, path, header = r.Method, r.URL.Path, r.Header.Clone()
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

		res, err := call(ctx, rpc.NewClient(server.Client(), server.URL+"/"))
		require.NoError(t, err)
		assert.Equal(t, "v1.2.3", res.GetVersion())
		assert.Equal(t, http.MethodPost, method)
		assert.Equal(t, procedure, path, "a trailing slash of the base URL is dropped")
		assert.Equal(t, "application/proto", header.Get("Content-Type"))
		assert.Equal(t, "1", header.Get("Connect-Protocol-Version"))
		timeout, err := strconv.Atoi(header.Get("Connect-Timeout-Ms"))
		require.NoError(t, err, "the context deadline travels as Connect-Timeout-Ms")
		assert.Positive(t, timeout)
		assert.LessOrEqual(t, timeout, int(time.Minute.Milliseconds()))
	})
	t.Run("sends no timeout without a deadline", func(t *testing.T) {
		var header http.Header
		server := serve(t, func(w http.ResponseWriter, r *http.Request) {
			header = r.Header.Clone()
			w.WriteHeader(http.StatusNotFound)
		})
		_, err := callServer(t.Context(), server)
		require.Error(t, err)
		assert.Empty(t, header.Values("Connect-Timeout-Ms"))
	})

	timeoutTests := []struct {
		timeout time.Duration
		want    string
	}{
		{timeout: 2 * time.Millisecond, want: "2"},
		{timeout: 1500 * time.Microsecond, want: "2"},
		{timeout: 300 * time.Microsecond, want: "1"},
	}
	for _, tc := range timeoutTests {
		t.Run(fmt.Sprintf("sends a deadline %s away as a timeout of %s ms", tc.timeout, tc.want), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), tc.timeout)
				defer cancel()
				var header http.Header
				httpClient := doFunc(func(req *http.Request) (*http.Response, error) {
					header = req.Header.Clone()
					return nil, errors.New("stop")
				})
				_, err := call(ctx, rpc.NewClient(httpClient, "http://unix"))
				require.Error(t, err)
				assert.Equal(t, []string{tc.want}, header.Values("Connect-Timeout-Ms"))
			})
		})
	}

	responseTests := []struct {
		name    string
		handler http.HandlerFunc
		code    rpc.Code
		message string
	}{
		{
			name:    "Connect error",
			handler: respond(http.StatusNotFound, "application/json", `{"code":"not_found","message":"no such plugin"}`),
			code:    rpc.CodeNotFound,
			message: "no such plugin",
		},
		{
			name:    "Connect error without a message",
			handler: respond(http.StatusInternalServerError, "application/json", `{"code":"internal"}`),
			code:    rpc.CodeInternal,
		},
		{
			name:    "JSON error without a code",
			handler: respond(http.StatusServiceUnavailable, "application/json; charset=utf-8", `{"message":"starting"}`),
			code:    rpc.CodeUnavailable,
			message: "starting",
		},
		{
			name:    "JSON error with a code outside the protocol",
			handler: respond(http.StatusTooManyRequests, "application/json", `{"code":"bogus","message":"slow down"}`),
			code:    rpc.CodeUnavailable,
			message: "slow down",
		},
		{
			name:    "malformed JSON error",
			handler: respond(http.StatusUnauthorized, "application/json", `{`),
			code:    rpc.CodeUnauthenticated,
			message: "401 Unauthorized",
		},
		{
			name:    "procedure the server does not serve",
			handler: http.NotFound,
			code:    rpc.CodeUnimplemented,
			message: "404 Not Found",
		},
		{
			name:    "error that is not JSON",
			handler: respond(http.StatusForbidden, "text/plain", "denied"),
			code:    rpc.CodePermissionDenied,
			message: "403 Forbidden",
		},
		{
			name:    "bad request",
			handler: respond(http.StatusBadRequest, "", ""),
			code:    rpc.CodeInternal,
			message: "400 Bad Request",
		},
		{
			name:    "other status",
			handler: respond(http.StatusTeapot, "text/plain", "short and stout"),
			code:    rpc.CodeUnknown,
			message: "418 I'm a teapot",
		},
		{
			name:    "response that is not protobuf",
			handler: respond(http.StatusOK, "text/html", "<html></html>"),
			code:    rpc.CodeUnknown,
			message: `invalid content-type "text/html": expecting "application/proto"`,
		},
	}
	for _, tc := range responseTests {
		t.Run("server sends a "+tc.name, func(t *testing.T) {
			_, err := callServer(t.Context(), serve(t, tc.handler))
			assert.Equal(t, rpc.NewError(tc.code, errors.New(tc.message)), err)
		})
	}
	t.Run("server sends a malformed message", func(t *testing.T) {
		_, err := callServer(t.Context(), serve(t, respond(http.StatusOK, "application/proto", "\xff")))
		assert.Equal(t, rpc.CodeInternal, rpc.CodeOf(err))
		assert.ErrorContains(t, err, "unmarshal response")
	})

	unreadTests := []struct {
		name        string
		status      int
		contentType string
		code        rpc.Code
		message     string
	}{
		{
			name:        "an error that is not JSON",
			status:      http.StatusServiceUnavailable,
			contentType: "text/plain",
			code:        rpc.CodeUnavailable,
			message:     "503 Service Unavailable",
		},
		{
			name:        "a response that is not protobuf",
			status:      http.StatusOK,
			contentType: "text/html",
			code:        rpc.CodeUnknown,
			message:     `invalid content-type "text/html": expecting "application/proto"`,
		},
	}
	for _, tc := range unreadTests {
		t.Run("does not read the body of "+tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			_, err := callServer(ctx, stallingServer(t, tc.status, tc.contentType))
			assert.Equal(t, rpc.NewError(tc.code, errors.New(tc.message)), err)
		})
	}

	t.Run("reports an unreachable server as unavailable", func(t *testing.T) {
		server := serve(t, respond(http.StatusOK, "application/proto", ""))
		server.Close()
		_, err := callServer(t.Context(), server)
		assert.Equal(t, rpc.CodeUnavailable, rpc.CodeOf(err))
		assert.NotContains(t, err.Error(), server.URL)
	})
	t.Run("reports a dropped connection as unavailable", func(t *testing.T) {
		server := serve(t, func(w http.ResponseWriter, _ *http.Request) {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = conn.Close()
		})
		_, err := callServer(t.Context(), server)
		assert.Equal(t, rpc.NewError(rpc.CodeUnavailable, io.EOF), err)
	})
	t.Run("reports a truncated response as unavailable", func(t *testing.T) {
		server := serve(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/proto")
			w.Header().Set("Content-Length", "2")
			_, _ = w.Write([]byte{0x0a})
		})
		_, err := callServer(t.Context(), server)
		require.EqualError(t, err, "unavailable: read response: unexpected EOF")
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
	t.Run("reports the timeout of the HTTP client as deadline_exceeded", func(t *testing.T) {
		server := hangingServer(t)
		httpClient := &http.Client{Transport: server.Client().Transport, Timeout: 50 * time.Millisecond}
		_, err := call(t.Context(), rpc.NewClient(httpClient, server.URL))
		assert.Equal(t, rpc.CodeDeadlineExceeded, rpc.CodeOf(err))
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.NotContains(t, err.Error(), server.URL)
	})
	t.Run("returns a coded error of the HTTP client unchanged", func(t *testing.T) {
		want := rpc.NewError(rpc.CodeAborted, errors.New("stop"))
		httpClient := doFunc(func(*http.Request) (*http.Response, error) { return nil, want })
		_, err := call(t.Context(), rpc.NewClient(httpClient, "http://unix"))
		assert.Same(t, want, err)
	})

	t.Run("keeps a context deadline matchable", func(t *testing.T) {
		server := hangingServer(t)
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		_, err := callServer(ctx, server)
		assert.Equal(t, rpc.CodeDeadlineExceeded, rpc.CodeOf(err))
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.NotContains(t, err.Error(), server.URL)
	})
	t.Run("keeps a context deadline with a cause matchable", func(t *testing.T) {
		cause := errors.New("ping timed out")
		ctx, cancel := context.WithTimeoutCause(t.Context(), 50*time.Millisecond, cause)
		defer cancel()
		_, err := callServer(ctx, hangingServer(t))
		require.EqualError(t, err, "deadline_exceeded: context deadline exceeded: ping timed out")
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorIs(t, err, cause)
	})
	t.Run("keeps a context cancellation matchable", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		_, err := callServer(ctx, blockingServer(t, func(http.ResponseWriter) { cancel() }))
		assert.Equal(t, rpc.NewError(rpc.CodeCanceled, context.Canceled), err)
	})
	t.Run("keeps a context deadline matchable while it reads a JSON error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		_, err := callServer(ctx, stallingServer(t, http.StatusServiceUnavailable, "application/json"))
		assert.Equal(t, rpc.CodeDeadlineExceeded, rpc.CodeOf(err))
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	lateError := func(end func()) doFunc {
		return func(req *http.Request) (*http.Response, error) {
			end()
			<-req.Context().Done()
			return &http.Response{
				Status:     "500 Internal Server Error",
				StatusCode: http.StatusInternalServerError,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"code":"internal","message":"provider: context deadline exceeded"}`)),
			}, nil
		}
	}
	t.Run("reports the context deadline over an error the server answers late", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		defer cancel()
		_, err := call(ctx, rpc.NewClient(lateError(func() {}), "http://unix"))
		assert.Equal(t, rpc.NewError(rpc.CodeDeadlineExceeded, context.DeadlineExceeded), err)
	})
	t.Run("reports the context cancellation over an error the server answers late", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		_, err := call(ctx, rpc.NewClient(lateError(cancel), "http://unix"))
		assert.Equal(t, rpc.NewError(rpc.CodeCanceled, context.Canceled), err)
	})
}

func TestError(t *testing.T) {
	t.Parallel()
	cause := errors.New("no such plugin")
	err := rpc.NewError(rpc.CodeNotFound, cause)

	assert.Equal(t, rpc.CodeNotFound, err.Code())
	assert.Equal(t, "no such plugin", err.Message())
	require.EqualError(t, err, "not_found: no such plugin")
	require.ErrorIs(t, err, cause)
	require.EqualError(t, rpc.NewError(rpc.CodeNotFound, nil), "not_found")

	assert.Equal(t, rpc.CodeNotFound, rpc.CodeOf(err))
	assert.Equal(t, rpc.CodeNotFound, rpc.CodeOf(fmt.Errorf("lookup: %w", err)))
	assert.Equal(t, rpc.CodeUnknown, rpc.CodeOf(cause))
	assert.Equal(t, rpc.CodeUnknown, rpc.CodeOf(nil))
}
