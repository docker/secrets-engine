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

	"github.com/docker/secrets-engine/x/api"
	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/ipc"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

type mockRegistrationHandler struct {
	registerRequests int
}

func (m *mockRegistrationHandler) RegisterPlugin(context.Context, *connect.Request[resolverv1.RegisterPluginRequest]) (*connect.Response[resolverv1.RegisterPluginResponse], error) {
	m.registerRequests++
	return connect.NewResponse(resolverv1.RegisterPluginResponse_builder{
		EngineName:     proto.String("mock"),
		EngineVersion:  proto.String("v1.0.0"),
		RequestTimeout: durationpb.New(10 * time.Second),
	}.Build()), nil
}

func Test_setup(t *testing.T) {
	t.Run("plugin shuts down its IPC when runtime calls shutdown", func(t *testing.T) {
		a, b := net.Pipe()
		httpMux := http.NewServeMux()
		mRegister := &mockRegistrationHandler{}
		httpMux.Handle(resolverv1connect.NewRegisterServiceHandler(mRegister))
		runtimeClosed := make(chan struct{})
		_, client, err := ipc.NewServerIPC(testhelper.TestLogger(t), a, httpMux, func(err error) {
			assert.ErrorIs(t, err, io.EOF)
			close(runtimeClosed)
		})
		require.NoError(t, err)
		mPlugin := &mockPlugin{}
		pluginClosed := make(chan struct{})
		closer, err := setup(t.Context(), cfg{Config{api.MustNewVersion("v1"), secrets.MustParsePattern("*"), testhelper.TestLogger(t)}, mPlugin, "foo", b, 5 * time.Second}, func(err error) {
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
