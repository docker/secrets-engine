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
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/timestamppb"

	healthv1 "github.com/docker/secrets-engine/client/api/health/v1"
	pluginsv1 "github.com/docker/secrets-engine/client/api/plugins/v1"
	resolverv1 "github.com/docker/secrets-engine/client/api/resolver/v1"
	clientconfig "github.com/docker/secrets-engine/client/config"
	"github.com/docker/secrets-engine/client/dockerhub"
	"github.com/docker/secrets-engine/client/version"
	"github.com/docker/secrets-engine/secrets"
)

type mockVersionService struct {
	version    string
	date       string
	commitHash string
}

func (m mockVersionService) GetVersion(_ *healthv1.GetVersionRequest) (*healthv1.GetVersionResponse, error) {
	return healthv1.GetVersionResponse_builder{
		Version:    proto.String(m.version),
		Date:       proto.String(m.date),
		CommitHash: proto.String(m.commitHash),
	}.Build(), nil
}

func mockVersionEngine(t *testing.T, version, date, commitHash string) string {
	t.Helper()
	socketPath := randomShortSocketName()
	m := mockVersionService{version: version, date: date, commitHash: commitHash}
	muxServer(t, socketPath, []handler{unary(t, "health.v1.VersionService.GetVersion", m.GetVersion)})
	return socketPath
}

type mockPluginsList struct {
	list []PluginInfo
}

func (m mockPluginsList) ListPlugins(_ *pluginsv1.ListPluginsRequest) (*pluginsv1.ListPluginsResponse, error) {
	var plugins []*pluginsv1.Plugin
	for _, plugin := range m.list {
		var name string
		if plugin.Name != nil {
			name = plugin.Name.String()
		}
		var version string
		if plugin.Version != nil {
			version = plugin.Version.String()
		}
		b := pluginsv1.Plugin_builder{
			Name:          proto.String(name),
			Version:       proto.String(version),
			Disabled:      proto.Bool(plugin.Disabled),
			External:      proto.Bool(plugin.External),
			Configurable:  proto.Bool(plugin.Configurable),
			RunStatus:     plugin.RunStatus.Enum(),
			StatusMessage: proto.String(plugin.StatusMessage),
		}
		switch {
		case plugin.SecretsProvider != nil:
			b.SecretsProvider = pluginsv1.SecretsProvider_builder{
				Pattern: proto.String(plugin.SecretsProvider.Pattern.String()),
			}.Build()
		case plugin.AccessControlModule != nil:
			b.AccessControlModule = pluginsv1.AccessControlModule_builder{}.Build()
		}
		plugins = append(plugins, b.Build())
	}
	return pluginsv1.ListPluginsResponse_builder{
		Plugins: plugins,
	}.Build(), nil
}

type handler struct {
	pattern string
	handler http.Handler
}

func muxServer(t *testing.T, socketPath string, handlers []handler) {
	t.Helper()
	_ = os.Remove(socketPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0o755))
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	mux := http.NewServeMux()
	for _, h := range handlers {
		mux.Handle(h.pattern, h.handler)
	}

	server := &http.Server{Handler: mux}

	go func() {
		_ = server.Serve(listener)
	}()

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		_ = server.Shutdown(shutdownCtx)
		_ = listener.Close()
		_ = os.RemoveAll(socketPath)
	})
}

func wrapHandler(pattern string, h http.Handler) handler {
	return handler{pattern: pattern, handler: h}
}

// randomShortSocketName creates a socket name string that avoids common pitfalls in tests.
// There are a bunch of opposing problems in unit tests with sockets:
// Ideally, we'd like to use t.TmpDir+something.sock -> too long socket name
// We can't just use local short file name -> clashes when running tests in parallel
// We can't use t.ChDir + short name -> t.ChDir does not allow t.Parallel
// -> we use a short local but randomized socket path
func randomShortSocketName() string {
	return rand.Text() + ".sock"
}

func unary[Req, Resp proto.Message](t *testing.T, method protoreflect.FullName, fn func(Req) (Resp, error)) handler {
	t.Helper()
	var (
		reqType  Req
		respType Resp
	)
	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(method)
	require.NoError(t, err)
	rpc, ok := desc.(protoreflect.MethodDescriptor)
	require.True(t, ok, "%s is not an RPC method", method)
	require.Equal(t, rpc.Input().FullName(), reqType.ProtoReflect().Descriptor().FullName())
	require.Equal(t, rpc.Output().FullName(), respType.ProtoReflect().Descriptor().FullName())

	serve := func(r *http.Request) ([]byte, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		req := reqType.ProtoReflect().New().Interface().(Req)
		if err := proto.Unmarshal(body, req); err != nil {
			return nil, err
		}
		resp, err := fn(req)
		if err != nil {
			return nil, err
		}
		return proto.Marshal(resp)
	}
	procedure := "/" + string(rpc.Parent().FullName()) + "/" + string(rpc.Name())
	return wrapHandler(procedure, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := serve(r)
		if err != nil {
			rpcErr, ok := errors.AsType[*RPCError](err)
			if !ok {
				rpcErr = &RPCError{Code: CodeUnknown, Message: err.Error()}
			}
			w.Header().Set("Content-Type", contentTypeJSON)
			w.WriteHeader(statusFromCode(rpcErr.Code))
			_ = json.NewEncoder(w).Encode(struct {
				Code    Code   `json:"code"`
				Message string `json:"message,omitempty"`
			}{rpcErr.Code, rpcErr.Message})
			return
		}
		w.Header().Set("Content-Type", contentTypeProto)
		_, _ = w.Write(data)
	}))
}

// https://connectrpc.com/docs/protocol#error-codes
func statusFromCode(code Code) int {
	switch code {
	case CodeCanceled:
		return 499
	case CodeInvalidArgument, CodeFailedPrecondition, CodeOutOfRange:
		return http.StatusBadRequest
	case CodeUnauthenticated:
		return http.StatusUnauthorized
	case CodePermissionDenied:
		return http.StatusForbidden
	case CodeNotFound:
		return http.StatusNotFound
	case CodeAlreadyExists, CodeAborted:
		return http.StatusConflict
	case CodeResourceExhausted:
		return http.StatusTooManyRequests
	case CodeUnimplemented:
		return http.StatusNotImplemented
	case CodeUnavailable:
		return http.StatusServiceUnavailable
	case CodeDeadlineExceeded:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}

func mockListPluginsEngine(t *testing.T, plugins []PluginInfo) string {
	t.Helper()
	socketPath := randomShortSocketName()
	m := mockPluginsList{list: plugins}
	muxServer(t, socketPath, []handler{unary(t, "plugins.v1.PluginManagementService.ListPlugins", m.ListPlugins)})
	return socketPath
}

func Test_ListPlugins(t *testing.T) {
	t.Parallel()
	t.Run("external and internal configurable plugins", func(t *testing.T) {
		plugins := []PluginInfo{
			{
				Name:            version.MustNewName("foo"),
				Version:         version.MustNewVersion("v1"),
				SecretsProvider: &SecretsProviderMetadata{Pattern: secrets.MustParsePattern("**")},
				Configurable:    true,
				Disabled:        true,
			},
			{
				Name:            version.MustNewName("bar"),
				Version:         version.MustNewVersion("v1"),
				SecretsProvider: &SecretsProviderMetadata{Pattern: secrets.MustParsePattern("**")},
				External:        true,
				RunStatus:       pluginsv1.RunStatus_RUN_STATUS_CRASHED,
				StatusMessage:   "exit status 1: connection refused",
			},
			{
				Name:                version.MustNewName("baz"),
				Version:             version.MustNewVersion("v1"),
				AccessControlModule: &AccessControlModuleMetadata{},
				External:            true,
			},
		}
		socket := mockListPluginsEngine(t, plugins)
		client, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		m, err := PluginManagementFromClient(client)
		require.NoError(t, err)
		result, err := m.ListPlugins(t.Context())
		require.NoError(t, err)
		assert.Equal(t, plugins, result)
	})
	t.Run("no plugins", func(t *testing.T) {
		var plugins []PluginInfo
		socket := mockListPluginsEngine(t, plugins)
		client, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		m, err := PluginManagementFromClient(client)
		require.NoError(t, err)
		result, err := m.ListPlugins(t.Context())
		require.NoError(t, err)
		assert.Empty(t, result)
	})
	t.Run("mix of valid and invalid plugin info", func(t *testing.T) {
		plugins := []PluginInfo{
			{
				Name: version.MustNewName("foo"),
			},
			{
				Name:            version.MustNewName("bar"),
				Version:         version.MustNewVersion("v1"),
				SecretsProvider: &SecretsProviderMetadata{Pattern: secrets.MustParsePattern("**")},
			},
		}
		socket := mockListPluginsEngine(t, plugins)
		client, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		m, err := PluginManagementFromClient(client)
		require.NoError(t, err)
		result, err := m.ListPlugins(t.Context())
		require.NoError(t, err)

		assert.Equal(t, []PluginInfo{
			{
				Name:            version.MustNewName("bar"),
				Version:         version.MustNewVersion("v1"),
				SecretsProvider: &SecretsProviderMetadata{Pattern: secrets.MustParsePattern("**")},
			},
		}, result)
	})
}

type mockPluginToggle struct {
	enabled  []string
	disabled []string
	err      error
}

func (m *mockPluginToggle) EnablePlugin(req *pluginsv1.EnablePluginRequest) (*pluginsv1.EnablePluginResponse, error) {
	m.enabled = append(m.enabled, req.GetName())
	if m.err != nil {
		return nil, m.err
	}
	return pluginsv1.EnablePluginResponse_builder{}.Build(), nil
}

func (m *mockPluginToggle) DisablePlugin(req *pluginsv1.DisablePluginRequest) (*pluginsv1.DisablePluginResponse, error) {
	m.disabled = append(m.disabled, req.GetName())
	if m.err != nil {
		return nil, m.err
	}
	return pluginsv1.DisablePluginResponse_builder{}.Build(), nil
}

func Test_EnableDisablePlugin(t *testing.T) {
	t.Parallel()
	start := func(t *testing.T, m *mockPluginToggle) PluginManagement {
		t.Helper()
		socketPath := randomShortSocketName()
		muxServer(t, socketPath, []handler{
			unary(t, "plugins.v1.PluginManagementService.EnablePlugin", m.EnablePlugin),
			unary(t, "plugins.v1.PluginManagementService.DisablePlugin", m.DisablePlugin),
		})
		c, err := New(WithSocketPath(socketPath))
		require.NoError(t, err)
		pm, err := PluginManagementFromClient(c)
		require.NoError(t, err)
		return pm
	}
	t.Run("forwards the plugin name", func(t *testing.T) {
		m := &mockPluginToggle{}
		pm := start(t, m)
		require.NoError(t, pm.EnablePlugin(t.Context(), "foo"))
		require.NoError(t, pm.DisablePlugin(t.Context(), "bar"))
		assert.Equal(t, []string{"foo"}, m.enabled)
		assert.Equal(t, []string{"bar"}, m.disabled)
	})
	t.Run("returns the engine error", func(t *testing.T) {
		want := &RPCError{Code: CodeNotFound, Message: `plugin "foo" not found`}
		pm := start(t, &mockPluginToggle{err: want})
		assert.Equal(t, want, pm.EnablePlugin(t.Context(), "foo"))
		assert.Equal(t, want, pm.DisablePlugin(t.Context(), "foo"))
	})
}

type mockResolverService struct {
	envelopes []*resolverv1.GetSecretsResponse_Envelope
	err       error
	pattern   string
}

func (m *mockResolverService) GetSecrets(req *resolverv1.GetSecretsRequest) (*resolverv1.GetSecretsResponse, error) {
	m.pattern = req.GetPattern()
	if m.err != nil {
		return nil, m.err
	}
	return resolverv1.GetSecretsResponse_builder{Envelopes: m.envelopes}.Build(), nil
}

func Test_GetSecrets(t *testing.T) {
	t.Parallel()
	getSecrets := func(t *testing.T, m *mockResolverService) ([]Envelope, error) {
		t.Helper()
		socketPath := randomShortSocketName()
		muxServer(t, socketPath, []handler{unary(t, "resolver.v1.ResolverService.GetSecrets", m.GetSecrets)})
		c, err := New(WithSocketPath(socketPath))
		require.NoError(t, err)
		return c.GetSecrets(t.Context(), MustParsePattern("acme/**"))
	}
	t.Run("forwards the pattern and returns the envelopes", func(t *testing.T) {
		createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		m := &mockResolverService{envelopes: []*resolverv1.GetSecretsResponse_Envelope{
			resolverv1.GetSecretsResponse_Envelope_builder{
				Id:         proto.String("acme/api-token"),
				Value:      []byte("s3cret"),
				Metadata:   map[string]string{"owner": "acme"},
				Provider:   proto.String("pass"),
				Version:    proto.String("v1"),
				CreatedAt:  timestamppb.New(createdAt),
				ResolvedAt: timestamppb.New(createdAt.Add(time.Hour)),
				ExpiresAt:  timestamppb.New(createdAt.Add(2 * time.Hour)),
			}.Build(),
			resolverv1.GetSecretsResponse_Envelope_builder{Value: []byte("no id")}.Build(),
		}}
		got, err := getSecrets(t, m)
		require.NoError(t, err)
		assert.Equal(t, "acme/**", m.pattern)
		assert.Equal(t, []Envelope{{
			ID:         MustParseID("acme/api-token"),
			Value:      []byte("s3cret"),
			Metadata:   map[string]string{"owner": "acme"},
			Provider:   "pass",
			Version:    "v1",
			CreatedAt:  createdAt,
			ResolvedAt: createdAt.Add(time.Hour),
			ExpiresAt:  createdAt.Add(2 * time.Hour),
		}}, got, "an envelope without a valid ID is dropped")
	})
	t.Run("not found", func(t *testing.T) {
		_, err := getSecrets(t, &mockResolverService{err: &RPCError{Code: CodeNotFound, Message: secrets.ErrNotFound.Error()}})
		assert.Equal(t, ErrSecretNotFound, err)
	})
	t.Run("returns other engine errors as RPCError", func(t *testing.T) {
		want := &RPCError{Code: CodePermissionDenied, Message: "denied by policy"}
		_, err := getSecrets(t, &mockResolverService{err: want})
		assert.Equal(t, want, err)
		assert.EqualError(t, err, "permission_denied: denied by policy")
	})
}

type mockAuthorizerService struct {
	expiry   time.Time
	decision *resolverv1.Decision // nil leaves the decision unset
	err      error
	patterns []string
}

func (m *mockAuthorizerService) Authorize(req *resolverv1.AuthorizeRequest) (*resolverv1.AuthorizeResponse, error) {
	m.patterns = req.GetPatterns()
	if m.err != nil {
		return nil, m.err
	}
	var expiresAt *timestamppb.Timestamp // nil leaves the expiry absent
	if !m.expiry.IsZero() {
		expiresAt = timestamppb.New(m.expiry)
	}
	return resolverv1.AuthorizeResponse_builder{
		ExpiresAt: expiresAt,
		Decision:  m.decision,
	}.Build(), nil
}

func mockAuthorizeEngine(t *testing.T, m *mockAuthorizerService) string {
	t.Helper()
	socketPath := randomShortSocketName()
	muxServer(t, socketPath, []handler{unary(t, "resolver.v1.AuthorizerService.Authorize", m.Authorize)})
	return socketPath
}

func Test_Authorize(t *testing.T) {
	t.Parallel()
	t.Run("forwards patterns and returns the decision", func(t *testing.T) {
		expiry := time.Now().Add(time.Hour).UTC()
		m := &mockAuthorizerService{expiry: expiry, decision: resolverv1.Decision_DECISION_ALLOW.Enum()}
		socket := mockAuthorizeEngine(t, m)
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)

		got, err := c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"), MustParsePattern("acme/api-token"))
		require.NoError(t, err)
		assert.True(t, got.Expiry.Equal(expiry), "expiry must round-trip")
		assert.True(t, got.Allow)
		assert.Equal(t, []string{"docker/auth/hub/joe", "acme/api-token"}, m.patterns)
	})
	t.Run("decodes an absent expiry as the zero time", func(t *testing.T) {
		m := &mockAuthorizerService{decision: resolverv1.Decision_DECISION_ALLOW.Enum()}
		socket := mockAuthorizeEngine(t, m)
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)

		got, err := c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"))
		require.NoError(t, err)
		assert.True(t, got.Allow)
		assert.True(t, got.Expiry.IsZero(), "an absent expiry means the decision never expires")
	})
	t.Run("returns a deny decision without an error", func(t *testing.T) {
		m := &mockAuthorizerService{decision: resolverv1.Decision_DECISION_DENY.Enum()}
		socket := mockAuthorizeEngine(t, m)
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)

		got, err := c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"))
		require.NoError(t, err)
		assert.False(t, got.Allow)
	})
	t.Run("treats a missing decision as deny", func(t *testing.T) {
		m := &mockAuthorizerService{}
		socket := mockAuthorizeEngine(t, m)
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)

		got, err := c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"))
		require.NoError(t, err)
		assert.False(t, got.Allow, "a decision must be explicit to grant access")
	})
	t.Run("denied", func(t *testing.T) {
		m := &mockAuthorizerService{err: &RPCError{Code: CodePermissionDenied, Message: secrets.ErrAccessDenied.Error()}}
		socket := mockAuthorizeEngine(t, m)
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		_, err = c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"))
		require.ErrorIs(t, err, ErrAccessDenied)
	})
	t.Run("unavailable daemon", func(t *testing.T) {
		socketPath := randomShortSocketName()
		c, err := New(WithSocketPath(socketPath))
		require.NoError(t, err)
		_, err = c.Authorize(t.Context(), MustParsePattern("docker/auth/hub/joe"))
		require.ErrorIs(t, err, ErrSecretsEngineNotRunning)
	})
}

func Test_Version(t *testing.T) {
	t.Parallel()
	t.Run("returns version info", func(t *testing.T) {
		socket := mockVersionEngine(t, "v1.2.3", "2026-03-26", "abc1234")
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		dv, err := c.Version(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "v1.2.3", dv.Version.String())
		assert.Equal(t, "2026-03-26", dv.Date)
		assert.Equal(t, "abc1234", dv.CommitHash)
	})
	t.Run("unavailable daemon", func(t *testing.T) {
		socketPath := randomShortSocketName()
		c, err := New(WithSocketPath(socketPath))
		require.NoError(t, err)
		_, err = c.Version(t.Context())
		require.ErrorIs(t, err, ErrSecretsEngineNotRunning)
	})
}

func TestSecretsEngineUnavailable(t *testing.T) {
	socketPath := randomShortSocketName()
	client, err := New(WithSocketPath(socketPath))
	require.NoError(t, err)
	m, err := PluginManagementFromClient(client)
	require.NoError(t, err)
	_, err = m.ListPlugins(t.Context())
	require.ErrorIs(t, err, ErrSecretsEngineNotRunning)
	_, err = client.GetSecrets(t.Context(), secrets.MustParsePattern("**"))
	require.ErrorIs(t, err, ErrSecretsEngineNotRunning)
}

func TestHubAuth(t *testing.T) {
	client, err := New(WithSocketPath(randomShortSocketName()))
	require.NoError(t, err)
	assert.NotNil(t, client.HubAuth())
	assert.NotNil(t, client.HubAuth(dockerhub.Staging()))
}

func TestIsDialError(t *testing.T) {
	require.True(t, isDialError(&net.OpError{
		Op: "dial",
	}))
	require.True(t, isDialError(&net.OpError{
		Op: "connect",
	}))
	require.False(t, isDialError(nil))
}

func TestConnectError(t *testing.T) {
	dialErr := func(err error) error {
		return &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", err)}
	}
	sentinels := []error{ErrSecretsEngineNotRunning, ErrSecretsEnginePermissionDenied, ErrSecretsEngineTimeout}
	tests := []struct {
		name     string
		err      error
		reason   ConnectReason
		sentinel error
	}{
		{name: "missing socket", err: dialErr(syscall.ENOENT), reason: ReasonNotRunning, sentinel: ErrSecretsEngineNotRunning},
		{name: "nothing listening", err: dialErr(errConnRefused), reason: ReasonNotRunning, sentinel: ErrSecretsEngineNotRunning},
		{name: "permission denied", err: dialErr(syscall.EACCES), reason: ReasonPermissionDenied, sentinel: ErrSecretsEnginePermissionDenied},
		{name: "i/o timeout", err: &net.OpError{Op: "dial", Net: "unix", Err: os.ErrDeadlineExceeded}, reason: ReasonTimeout, sentinel: ErrSecretsEngineTimeout},
		{name: "context deadline", err: &net.OpError{Op: "dial", Net: "unix", Err: context.DeadlineExceeded}, reason: ReasonTimeout, sentinel: ErrSecretsEngineTimeout},
		{name: "other", err: dialErr(syscall.ECONNRESET), reason: ReasonUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := client{socketPath: "/run/engine.sock"}.connectError(tc.err)
			ce, ok := errors.AsType[*ConnectError](err)
			require.True(t, ok)
			assert.Equal(t, tc.reason, ce.Reason)
			assert.Equal(t, "/run/engine.sock", ce.SocketPath)
			require.ErrorIs(t, err, tc.err, "the dial error stays inspectable")
			for _, s := range sentinels {
				assert.Equal(t, s == tc.sentinel, errors.Is(err, s), "errors.Is(err, %q)", s)
			}
		})
	}
	t.Run("cancelled context is not an engine error", func(t *testing.T) {
		in := &net.OpError{Op: "dial", Net: "unix", Err: context.Canceled}
		err := client{socketPath: "/run/engine.sock"}.connectError(in)
		assert.Same(t, in, err)
	})
	t.Run("message", func(t *testing.T) {
		err := client{socketPath: "/run/engine.sock"}.connectError(dialErr(syscall.ENOENT))
		assert.Equal(t, "secrets engine is not running at /run/engine.sock: dial unix: connect: "+syscall.ENOENT.Error(), err.Error())
		err = client{}.connectError(dialErr(syscall.ECONNRESET))
		assert.Equal(t, "cannot connect to the secrets engine: dial unix: connect: "+syscall.ECONNRESET.Error(), err.Error())
	})
}

func TestConnectErrorHint(t *testing.T) {
	desktop := clientconfig.DesktopSocketPath()
	standalone := clientconfig.StandaloneSocketPath()
	denied := func(socket string) string {
		return "Your user lacks permission to connect to " + socket + ". Grant it read and write access to the socket and retry."
	}
	tests := []struct {
		name   string
		reason ConnectReason
		socket string
		hint   string
	}{
		{name: "desktop not running", reason: ReasonNotRunning, socket: desktop, hint: desktopNotRunningHint},
		{name: "desktop timeout", reason: ReasonTimeout, socket: desktop, hint: desktopTimeoutHint},
		{
			name:   "standalone not running",
			reason: ReasonNotRunning,
			socket: standalone,
			hint:   "Start the standalone secrets engine and retry: nothing is listening on " + strconv.Quote(standalone) + ".",
		},
		{
			name:   "standalone timeout",
			reason: ReasonTimeout,
			socket: standalone,
			hint:   "The standalone secrets engine on " + strconv.Quote(standalone) + " did not respond. Restart it and retry.",
		},
		{name: "custom socket not running", reason: ReasonNotRunning, socket: "/s.sock", hint: `Start the secrets engine and retry: nothing is listening on "/s.sock".`},
		{name: "custom socket timeout", reason: ReasonTimeout, socket: "/s.sock", hint: `The secrets engine on "/s.sock" did not respond. Restart it and retry.`},
		{name: "permission denied", reason: ReasonPermissionDenied, socket: "/s.sock", hint: denied(`"/s.sock"`)},
		{name: "permission denied on desktop socket", reason: ReasonPermissionDenied, socket: desktop, hint: denied(strconv.Quote(desktop))},
		{name: "permission denied without path", reason: ReasonPermissionDenied, hint: denied("the secrets engine socket")},
		{name: "not running without path", reason: ReasonNotRunning, hint: "Start the secrets engine and retry: nothing is listening on the secrets engine socket."},
		{name: "control characters in path are quoted", reason: ReasonNotRunning, socket: "/s\n.sock", hint: `Start the secrets engine and retry: nothing is listening on "/s\n.sock".`},
		{name: "unknown reason has no hint", reason: ReasonUnknown, socket: "/s.sock", hint: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ce := &ConnectError{Reason: tc.reason, SocketPath: tc.socket, Err: errors.New("dial")}
			assert.Equal(t, tc.hint, ce.Hint())
		})
	}
}

func TestConnectErrorFromSocket(t *testing.T) {
	getSecrets := func(t *testing.T, socketPath string) error {
		t.Helper()
		c, err := New(WithSocketPath(socketPath))
		require.NoError(t, err)
		_, err = c.GetSecrets(t.Context(), secrets.MustParsePattern("**"))
		return err
	}

	t.Run("missing socket", func(t *testing.T) {
		err := getSecrets(t, randomShortSocketName())
		require.ErrorIs(t, err, ErrSecretsEngineNotRunning)
	})
	t.Run("nothing listening", func(t *testing.T) {
		socketPath := randomShortSocketName()
		l, err := net.Listen("unix", socketPath)
		require.NoError(t, err)
		l.(*net.UnixListener).SetUnlinkOnClose(false)
		require.NoError(t, l.Close())
		t.Cleanup(func() { _ = os.Remove(socketPath) })

		err = getSecrets(t, socketPath)
		require.ErrorIs(t, err, ErrSecretsEngineNotRunning)
	})
	t.Run("permission denied", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs Unix file permissions enforced for the current user")
		}
		socketPath := randomShortSocketName()
		l, err := net.Listen("unix", socketPath)
		require.NoError(t, err)
		t.Cleanup(func() { _ = l.Close() })
		require.NoError(t, os.Chmod(socketPath, 0o000))

		err = getSecrets(t, socketPath)
		require.ErrorIs(t, err, ErrSecretsEnginePermissionDenied)
	})
}
