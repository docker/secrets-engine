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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pluginsv1 "github.com/docker/secrets-engine/plugin/api/plugins/v1"
	"github.com/docker/secrets-engine/plugin/api/plugins/v1/pluginsv1rpc"
	"github.com/docker/secrets-engine/plugin/rpc"
)

const (
	service   = "plugins.v1.RegisterService"
	procedure = "/" + service + "/RegisterPlugin"
)

type registerFunc = func(context.Context, *pluginsv1.RegisterPluginRequest) (*pluginsv1.RegisterPluginResponse, error)

func echo(_ context.Context, req *pluginsv1.RegisterPluginRequest) (*pluginsv1.RegisterPluginResponse, error) {
	return pluginsv1.RegisterPluginResponse_builder{EngineName: proto.String(req.GetName())}.Build(), nil
}

func fail(err error) registerFunc {
	return func(context.Context, *pluginsv1.RegisterPluginRequest) (*pluginsv1.RegisterPluginResponse, error) {
		return nil, err
	}
}

func serve(t *testing.T, unary registerFunc, opts ...rpc.HandlerOption) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(rpc.NewServiceHandler(service, rpc.NewUnaryHandler(procedure, unary, opts...)))
	return serveHTTP(t, mux)
}

func serveHTTP(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func call(ctx context.Context, server *httptest.Server, name string, opts ...rpc.ClientOption) (*pluginsv1.RegisterPluginResponse, error) {
	req := pluginsv1.RegisterPluginRequest_builder{Name: proto.String(name)}.Build()
	return rpc.CallUnary[pluginsv1.RegisterPluginResponse](ctx, rpc.NewClient(server.Client(), server.URL, opts...), procedure, req)
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

func TestCallUnary(t *testing.T) {
	t.Parallel()
	t.Run("returns the response", func(t *testing.T) {
		resp, err := call(t.Context(), serve(t, echo), "foo")
		require.NoError(t, err)
		assert.Equal(t, "foo", resp.GetEngineName())
	})
	t.Run("accepts a base URL with a trailing slash", func(t *testing.T) {
		server := serve(t, echo)
		client := rpc.NewClient(server.Client(), server.URL+"/")
		resp, err := rpc.CallUnary[pluginsv1.RegisterPluginResponse](t.Context(), client, procedure, &pluginsv1.RegisterPluginRequest{})
		require.NoError(t, err)
		assert.Empty(t, resp.GetEngineName())
	})

	deadlineTests := []struct {
		name    string
		timeout time.Duration
	}{
		{name: "carries the context deadline to the handler", timeout: time.Minute},
		{name: "gives the handler no deadline if the context has none"},
	}
	for _, tc := range deadlineTests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				hasDeadline bool
				remaining   time.Duration
			)
			server := serve(t, func(ctx context.Context, req *pluginsv1.RegisterPluginRequest) (*pluginsv1.RegisterPluginResponse, error) {
				deadline, ok := ctx.Deadline()
				hasDeadline, remaining = ok, time.Until(deadline)
				return echo(ctx, req)
			})
			ctx := t.Context()
			if tc.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.timeout)
				defer cancel()
			}
			_, err := call(ctx, server, "foo")
			require.NoError(t, err)
			require.Equal(t, tc.timeout > 0, hasDeadline)
			if hasDeadline {
				assert.Positive(t, remaining)
				assert.LessOrEqual(t, remaining, tc.timeout)
			}
		})
	}

	handlerErrorTests := []struct {
		name    string
		handler registerFunc
		code    rpc.Code
		message string
	}{
		{
			name:    "coded error",
			handler: fail(rpc.NewError(rpc.CodeNotFound, errors.New("no such plugin"))),
			code:    rpc.CodeNotFound,
			message: "no such plugin",
		},
		{
			name:    "wrapped coded error",
			handler: fail(fmt.Errorf("lookup: %w", rpc.NewError(rpc.CodePermissionDenied, errors.New("denied")))),
			code:    rpc.CodePermissionDenied,
			message: "denied",
		},
		{
			name:    "coded error without a message",
			handler: fail(rpc.NewError(rpc.CodeInternal, nil)),
			code:    rpc.CodeInternal,
		},
		{
			name:    "error with a code outside the protocol",
			handler: fail(rpc.NewError("bogus", errors.New("boom"))),
			code:    rpc.CodeUnknown,
			message: "boom",
		},
		{
			name:    "plain error",
			handler: fail(errors.New("boom")),
			code:    rpc.CodeUnknown,
			message: "boom",
		},
		{
			name:    "context cancellation",
			handler: fail(context.Canceled),
			code:    rpc.CodeCanceled,
			message: "context canceled",
		},
		{
			name:    "context deadline",
			handler: fail(fmt.Errorf("resolve: %w", context.DeadlineExceeded)),
			code:    rpc.CodeDeadlineExceeded,
			message: "resolve: context deadline exceeded",
		},
		{
			name:    "neither a response nor an error",
			handler: fail(nil),
			code:    rpc.CodeInternal,
			message: procedure + " returned neither a response nor an error",
		},
	}
	for _, tc := range handlerErrorTests {
		t.Run("handler returns a "+tc.name, func(t *testing.T) {
			_, err := call(t.Context(), serve(t, tc.handler), "foo")
			assert.Equal(t, rpc.NewError(tc.code, errors.New(tc.message)), err)
		})
	}

	responseTests := []struct {
		name    string
		handler http.HandlerFunc
		code    rpc.Code
		message string
	}{
		{
			name:    "procedure the server does not serve",
			handler: http.NotFound,
			code:    rpc.CodeUnimplemented,
			message: "404 Not Found",
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
			_, err := call(t.Context(), serveHTTP(t, tc.handler), "foo")
			assert.Equal(t, rpc.NewError(tc.code, errors.New(tc.message)), err)
		})
	}
	t.Run("server sends a malformed message", func(t *testing.T) {
		_, err := call(t.Context(), serveHTTP(t, respond(http.StatusOK, "application/proto", "\xff")), "foo")
		assert.Equal(t, rpc.CodeInternal, rpc.CodeOf(err))
		assert.ErrorContains(t, err, "unmarshal response")
	})

	t.Run("reports an unreachable server as unavailable", func(t *testing.T) {
		server := serve(t, echo)
		server.Close()
		_, err := call(t.Context(), server, "foo")
		assert.Equal(t, rpc.CodeUnavailable, rpc.CodeOf(err))
	})
	t.Run("keeps a context deadline matchable", func(t *testing.T) {
		server := blockingServer(t, func() {})
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		_, err := call(ctx, server, "foo")
		assert.Equal(t, rpc.CodeDeadlineExceeded, rpc.CodeOf(err))
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})
	t.Run("keeps a context cancellation matchable", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		_, err := call(ctx, blockingServer(t, cancel), "foo")
		assert.Equal(t, rpc.CodeCanceled, rpc.CodeOf(err))
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// blockingServer serves a handler that calls onRequest and then blocks until the test ends.
func blockingServer(t *testing.T, onRequest func()) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	server := serve(t, func(context.Context, *pluginsv1.RegisterPluginRequest) (*pluginsv1.RegisterPluginResponse, error) {
		onRequest()
		<-release
		return nil, errors.New("released")
	})
	t.Cleanup(func() { close(release) })
	return server
}

func post(t *testing.T, server *httptest.Server, method string, header map[string]string, body []byte) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, server.URL+procedure, bytes.NewReader(body))
	require.NoError(t, err)
	for key, value := range header {
		req.Header.Set(key, value)
	}
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(data)
}

func TestHandler(t *testing.T) {
	t.Parallel()
	request, err := proto.Marshal(pluginsv1.RegisterPluginRequest_builder{Name: proto.String("foo")}.Build())
	require.NoError(t, err)

	acceptedTests := []struct {
		name   string
		header map[string]string
	}{
		{name: "a bare request", header: map[string]string{"Content-Type": "application/proto"}},
		{name: "a content type with parameters", header: map[string]string{"Content-Type": "Application/Proto; charset=utf-8"}},
		{name: "the protocol version", header: map[string]string{"Content-Type": "application/proto", "Connect-Protocol-Version": "1"}},
		{name: "the identity encoding", header: map[string]string{"Content-Type": "application/proto", "Content-Encoding": "identity"}},
		{name: "a timeout", header: map[string]string{"Content-Type": "application/proto", "Connect-Timeout-Ms": "9999999999"}},
	}
	for _, tc := range acceptedTests {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			resp, body := post(t, serve(t, echo), http.MethodPost, tc.header, request)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "application/proto", resp.Header.Get("Content-Type"))
			msg := &pluginsv1.RegisterPluginResponse{}
			require.NoError(t, proto.Unmarshal([]byte(body), msg))
			assert.Equal(t, "foo", msg.GetEngineName())
		})
	}

	t.Run("rejects other methods", func(t *testing.T) {
		resp, _ := post(t, serve(t, echo), http.MethodGet, nil, nil)
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		assert.Equal(t, http.MethodPost, resp.Header.Get("Allow"))
	})
	for _, contentType := range []string{"", "application/json", "application/grpc"} {
		t.Run(fmt.Sprintf("rejects the content type %q", contentType), func(t *testing.T) {
			resp, _ := post(t, serve(t, echo), http.MethodPost, map[string]string{"Content-Type": contentType}, request)
			assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
			assert.Equal(t, "application/proto", resp.Header.Get("Accept-Post"))
		})
	}

	rejectedTests := []struct {
		name   string
		header map[string]string
		body   []byte
		status int
		want   string
	}{
		{
			name:   "another protocol version",
			header: map[string]string{"Connect-Protocol-Version": "2"},
			body:   request,
			status: http.StatusBadRequest,
			want:   `{"code":"invalid_argument","message":"Connect-Protocol-Version must be \"1\": got \"2\""}`,
		},
		{
			name:   "a compressed request",
			header: map[string]string{"Content-Encoding": "gzip"},
			body:   request,
			status: http.StatusNotImplemented,
			want:   `{"code":"unimplemented","message":"unknown compression \"gzip\": supported encodings are identity"}`,
		},
		{
			name:   "a timeout that is not a number",
			header: map[string]string{"Connect-Timeout-Ms": "soon"},
			body:   request,
			status: http.StatusBadRequest,
			want:   `{"code":"invalid_argument","message":"invalid Connect-Timeout-Ms \"soon\""}`,
		},
		{
			name:   "a negative timeout",
			header: map[string]string{"Connect-Timeout-Ms": "-1"},
			body:   request,
			status: http.StatusBadRequest,
			want:   `{"code":"invalid_argument","message":"invalid Connect-Timeout-Ms \"-1\""}`,
		},
		{
			name:   "a timeout of more than ten digits",
			header: map[string]string{"Connect-Timeout-Ms": "10000000000"},
			body:   request,
			status: http.StatusBadRequest,
			want:   `{"code":"invalid_argument","message":"invalid Connect-Timeout-Ms \"10000000000\""}`,
		},
		{
			name:   "a request whose timeout has passed",
			header: map[string]string{"Connect-Timeout-Ms": "0"},
			body:   request,
			status: http.StatusGatewayTimeout,
			want:   `{"code":"deadline_exceeded","message":"context deadline exceeded"}`,
		},
	}
	for _, tc := range rejectedTests {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			called := false
			server := serve(t, func(ctx context.Context, req *pluginsv1.RegisterPluginRequest) (*pluginsv1.RegisterPluginResponse, error) {
				called = true
				return echo(ctx, req)
			})
			tc.header["Content-Type"] = "application/proto"
			resp, body := post(t, server, http.MethodPost, tc.header, tc.body)
			assert.Equal(t, tc.status, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
			assert.JSONEq(t, tc.want, body)
			assert.False(t, called)
		})
	}
	t.Run("rejects a malformed message", func(t *testing.T) {
		resp, body := post(t, serve(t, echo), http.MethodPost, map[string]string{"Content-Type": "application/proto"}, []byte("\xff"))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, body, `{"code":"invalid_argument","message":"unmarshal request: `)
	})

	statusTests := map[rpc.Code]int{
		rpc.CodeCanceled:           499,
		rpc.CodeUnknown:            500,
		rpc.CodeInvalidArgument:    400,
		rpc.CodeDeadlineExceeded:   504,
		rpc.CodeNotFound:           404,
		rpc.CodeAlreadyExists:      409,
		rpc.CodePermissionDenied:   403,
		rpc.CodeResourceExhausted:  429,
		rpc.CodeFailedPrecondition: 400,
		rpc.CodeAborted:            409,
		rpc.CodeOutOfRange:         400,
		rpc.CodeUnimplemented:      501,
		rpc.CodeInternal:           500,
		rpc.CodeUnavailable:        503,
		rpc.CodeDataLoss:           500,
		rpc.CodeUnauthenticated:    401,
	}
	for code, status := range statusTests {
		t.Run(fmt.Sprintf("answers %s with status %d", code, status), func(t *testing.T) {
			server := serve(t, fail(rpc.NewError(code, errors.New("boom"))))
			resp, body := post(t, server, http.MethodPost, map[string]string{"Content-Type": "application/proto"}, request)
			assert.Equal(t, status, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
			assert.JSONEq(t, fmt.Sprintf(`{"code":%q,"message":"boom"}`, code), body)
		})
	}
	t.Run("omits an empty message", func(t *testing.T) {
		server := serve(t, fail(rpc.NewError(rpc.CodeInternal, nil)))
		_, body := post(t, server, http.MethodPost, map[string]string{"Content-Type": "application/proto"}, request)
		assert.Equal(t, `{"code":"internal"}`, body)
	})
}

func TestWithInterceptors(t *testing.T) {
	t.Parallel()
	tracer := func(trace *[]string, name string) rpc.Interceptor {
		return func(next rpc.UnaryFunc) rpc.UnaryFunc {
			return func(ctx context.Context, req proto.Message) (proto.Message, error) {
				*trace = append(*trace, name+" in")
				resp, err := next(ctx, req)
				*trace = append(*trace, name+" out")
				return resp, err
			}
		}
	}
	reject := func(next rpc.UnaryFunc) rpc.UnaryFunc {
		return func(ctx context.Context, req proto.Message) (proto.Message, error) {
			if msg, ok := req.(*pluginsv1.RegisterPluginRequest); ok && msg.GetName() == "mallory" {
				return nil, rpc.NewError(rpc.CodePermissionDenied, errors.New("mallory may not register"))
			}
			return next(ctx, req)
		}
	}
	swap := func(rpc.UnaryFunc) rpc.UnaryFunc {
		return func(context.Context, proto.Message) (proto.Message, error) {
			return &pluginsv1.ShutdownResponse{}, nil
		}
	}

	t.Run("runs the first interceptor outermost, on the client and in the handler", func(t *testing.T) {
		var trace []string
		server := serve(t, func(ctx context.Context, req *pluginsv1.RegisterPluginRequest) (*pluginsv1.RegisterPluginResponse, error) {
			trace = append(trace, "handler")
			return echo(ctx, req)
		}, rpc.WithInterceptors(tracer(&trace, "c"), tracer(&trace, "d")), rpc.WithInterceptors(tracer(&trace, "e")))

		resp, err := call(t.Context(), server, "foo", rpc.WithInterceptors(tracer(&trace, "a")), rpc.WithInterceptors(tracer(&trace, "b")))
		require.NoError(t, err)
		assert.Equal(t, "foo", resp.GetEngineName())
		assert.Equal(t, []string{"a in", "b in", "c in", "d in", "e in", "handler", "e out", "d out", "c out", "b out", "a out"}, trace)
	})
	t.Run("lets a handler interceptor reject a request by its message", func(t *testing.T) {
		called := false
		server := serve(t, func(ctx context.Context, req *pluginsv1.RegisterPluginRequest) (*pluginsv1.RegisterPluginResponse, error) {
			called = true
			return echo(ctx, req)
		}, rpc.WithInterceptors(reject))

		_, err := call(t.Context(), server, "mallory")
		assert.Equal(t, rpc.NewError(rpc.CodePermissionDenied, errors.New("mallory may not register")), err)
		assert.False(t, called)

		_, err = call(t.Context(), server, "alice")
		require.NoError(t, err)
		assert.True(t, called)
	})
	t.Run("lets a client interceptor reject a request before it is sent", func(t *testing.T) {
		requests := 0
		server := serveHTTP(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
		_, err := call(t.Context(), server, "mallory", rpc.WithInterceptors(reject))
		assert.Equal(t, rpc.NewError(rpc.CodePermissionDenied, errors.New("mallory may not register")), err)
		assert.Zero(t, requests)
	})
	t.Run("reports a client interceptor that returns another message", func(t *testing.T) {
		_, err := call(t.Context(), serve(t, echo), "foo", rpc.WithInterceptors(swap))
		assert.Equal(t, rpc.NewError(rpc.CodeInternal, errors.New("unexpected response type *pluginsv1.ShutdownResponse")), err)
	})
	t.Run("reports a handler interceptor that passes on another message", func(t *testing.T) {
		server := serve(t, echo, rpc.WithInterceptors(func(next rpc.UnaryFunc) rpc.UnaryFunc {
			return func(ctx context.Context, _ proto.Message) (proto.Message, error) {
				return next(ctx, &pluginsv1.ShutdownRequest{})
			}
		}))
		_, err := call(t.Context(), server, "foo")
		assert.Equal(t, rpc.NewError(rpc.CodeInternal, errors.New("unexpected request type *pluginsv1.ShutdownRequest")), err)
	})
}

func TestGeneratedStubs(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.Handle(pluginsv1rpc.NewRegisterServiceHandler(pluginsv1rpc.UnimplementedRegisterServiceHandler{}))
	server := serveHTTP(t, mux)

	var seen []proto.Message
	client := pluginsv1rpc.NewRegisterServiceClient(server.Client(), server.URL, rpc.WithInterceptors(func(next rpc.UnaryFunc) rpc.UnaryFunc {
		return func(ctx context.Context, req proto.Message) (proto.Message, error) {
			seen = append(seen, req)
			return next(ctx, req)
		}
	}))
	req := pluginsv1.RegisterPluginRequest_builder{Name: proto.String("foo")}.Build()
	_, err := client.RegisterPlugin(t.Context(), req)

	assert.Equal(t, rpc.NewError(rpc.CodeUnimplemented, errors.New("plugins.v1.RegisterService.RegisterPlugin is not implemented")), err)
	require.Len(t, seen, 1)
	assert.Same(t, req, seen[0])
}

func TestError(t *testing.T) {
	t.Parallel()
	cause := errors.New("no such plugin")
	err := rpc.NewError(rpc.CodeNotFound, cause)

	assert.Equal(t, rpc.CodeNotFound, err.Code())
	assert.Equal(t, "no such plugin", err.Message())
	assert.EqualError(t, err, "not_found: no such plugin")
	assert.ErrorIs(t, err, cause)
	assert.EqualError(t, rpc.NewError(rpc.CodeNotFound, nil), "not_found")

	assert.Equal(t, rpc.CodeNotFound, rpc.CodeOf(err))
	assert.Equal(t, rpc.CodeNotFound, rpc.CodeOf(fmt.Errorf("lookup: %w", err)))
	assert.Equal(t, rpc.CodeUnknown, rpc.CodeOf(cause))
	assert.Equal(t, rpc.CodeUnknown, rpc.CodeOf(nil))
}
