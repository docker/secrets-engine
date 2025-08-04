package plugin

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/docker/secrets-engine/internal/api"
	resolverv1 "github.com/docker/secrets-engine/internal/api/resolver/v1"
	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/ipc"
	"github.com/docker/secrets-engine/internal/testhelper"
)

type mockRegistrationHandler struct {
	registerRequests int
}

func (m *mockRegistrationHandler) RegisterPlugin(context.Context, *connect.Request[resolverv1.RegisterPluginRequest]) (*connect.Response[resolverv1.RegisterPluginResponse], error) {
	m.registerRequests++
	return connect.NewResponse(resolverv1.RegisterPluginResponse_builder{
		EngineName:     proto.String("mock"),
		EngineVersion:  proto.String("1.0.0"),
		RequestTimeout: durationpb.New(10 * time.Second),
	}.Build()), nil
}

func Test_setup(t *testing.T) {
	t.Run("plugin shuts down its IPC when runtime calls shutdown", func(t *testing.T) {
		a, b := net.Pipe()
		httpMux := http.NewServeMux()
		mRegister := &mockRegistrationHandler{}
		httpMux.Handle(resolverv1connect.NewEngineServiceHandler(mRegister))
		runtimeClosed := make(chan struct{})
		_, client, err := ipc.NewServerIPC(testhelper.TestLogger(t), a, httpMux, func(err error) {
			assert.ErrorIs(t, err, io.EOF)
			close(runtimeClosed)
		})
		require.NoError(t, err)
		mPlugin := &mockPlugin{}
		pluginClosed := make(chan struct{})
		closer, err := setup(t.Context(), ipc.NewClientIPC, cfg{Config{api.MustNewVersion("1"), "*", testhelper.TestLogger(t)}, mPlugin, "foo", b, 5 * time.Second}, func(err error) {
			assert.NoError(t, err)
			close(pluginClosed)
		})
		require.NoError(t, err)
		_, err = resolverv1connect.NewPluginServiceClient(client, "http://unix").Shutdown(t.Context(), connect.NewRequest(resolverv1.ShutdownRequest_builder{}.Build()))
		assert.NoError(t, err)
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(pluginClosed))
		assert.NoError(t, closer.Close())
		assert.NoError(t, testhelper.WaitForClosedWithTimeout(runtimeClosed))
	})
}
