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

package commands

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client"
	pass "github.com/docker/secrets-engine/plugins/pass/store"
	"github.com/docker/secrets-engine/plugins/pass/teststore"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

var mockInfo = VersionInfo{
	Version: "v88",
	Commit:  "abc",
}

func Test_VersionCommand(t *testing.T) {
	t.Parallel()
	out, err := execute(t, VersionCommand(mockInfo), nil)
	assert.NoError(t, err)
	assert.Equal(t, "Version: v88\nCommit: abc\n", out)
}

func Test_SetCommand(t *testing.T) {
	t.Parallel()
	t.Run("ok", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := execute(t, SetCommand(), mock, "foo=bar=bar=bar")
		assert.NoError(t, err)
		assert.Empty(t, out)
		assertStoredValue(t, mock, "bar=bar=bar")
	})
	t.Run("from STDIN", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := executeWithStdin(t, SetCommand(), mock, "my\nmultiline\nvalue", "foo")
		assert.NoError(t, err)
		assert.Empty(t, out)
		assertStoredValue(t, mock, "my\nmultiline\nvalue")
	})
	t.Run("with --metadata flag", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := execute(t, SetCommand(), mock, "foo=bar", "--metadata", "name=bob", "--metadata", "expiry=2027-03-01")
		assert.NoError(t, err)
		assert.Empty(t, out)
		assertStoredValue(t, mock, "bar")
		assertStoredMetadata(t, mock, map[string]string{"name": "bob", "expiry": "2027-03-01"})
	})
	t.Run("from STDIN JSON with value and metadata", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := executeWithStdin(t, SetCommand(), mock, `{"secret":"bar","metadata":{"name":"bob"}}`, "foo")
		assert.NoError(t, err)
		assert.Empty(t, out)
		assertStoredValue(t, mock, "bar")
		assertStoredMetadata(t, mock, map[string]string{"name": "bob"})
	})
	t.Run("from STDIN JSON merged with --metadata flag wins on collision", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := executeWithStdin(t, SetCommand(), mock, `{"secret":"bar","metadata":{"name":"bob","extra":"thing"}}`, "foo", "--metadata", "name=alice")
		assert.NoError(t, err)
		assert.Empty(t, out)
		assertStoredValue(t, mock, "bar")
		assertStoredMetadata(t, mock, map[string]string{"name": "alice", "extra": "thing"})
	})
	t.Run("invalid --metadata flag (no =)", func(t *testing.T) {
		mock := teststore.NewMockStore()
		_, err := execute(t, SetCommand(), mock, "foo=bar", "--metadata", "invalid")
		assert.ErrorContains(t, err, "invalid metadata pair (expected key=value): invalid")
	})
	t.Run("store error", func(t *testing.T) {
		errSave := errors.New("save error")
		mock := teststore.NewMockStore(teststore.WithStoreSaveErr(errSave))
		out, err := execute(t, SetCommand(), mock, "foo=bar")
		assert.ErrorIs(t, err, errSave)
		assert.Equal(t, "Error: "+errSave.Error()+"\n", out)
	})
	t.Run("invalid id", func(t *testing.T) {
		errSave := errors.New("save error")
		mock := teststore.NewMockStore(teststore.WithStoreSaveErr(errSave))
		out, err := execute(t, SetCommand(), mock, "/foo=bar")
		errInvalidID := secrets.ErrInvalidID{ID: "/foo"}
		assert.ErrorIs(t, err, errInvalidID)
		assert.Equal(t, "Error: "+errInvalidID.Error()+"\n", out)
	})
	t.Run("existing secret hints --force", func(t *testing.T) {
		mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
			store.MustParseID("foo"): pass.NewPassValue([]byte("old")),
		}))
		out, err := execute(t, SetCommand(), mock, "foo=new")
		assert.ErrorIs(t, err, keychain.ErrDuplicateItem)
		assert.Equal(t, "Error: keychain item already exists\n\n"+duplicateItemHint+"\n", out)
		assertStoredValue(t, mock, "old")
	})
	t.Run("--force overwrites existing secret", func(t *testing.T) {
		// Make Save return an error so the test fails if --force does not
		// route the call through Upsert.
		mock := teststore.NewMockStore(
			teststore.WithStore(map[store.ID]store.Secret{
				store.MustParseID("foo"): pass.NewPassValue([]byte("old")),
			}),
			teststore.WithStoreSaveErr(errors.New("save should not be called when --force is set")),
		)
		out, err := execute(t, SetCommand(), mock, "foo=new", "--force")
		assert.NoError(t, err)
		assert.Empty(t, out)
		assertStoredValue(t, mock, "new")
	})
	t.Run("--force surfaces upsert error", func(t *testing.T) {
		errUpsert := errors.New("upsert error")
		mock := teststore.NewMockStore(teststore.WithStoreUpsertErr(errUpsert))
		out, err := execute(t, SetCommand(), mock, "foo=bar", "--force")
		assert.ErrorIs(t, err, errUpsert)
		assert.Equal(t, "Error: "+errUpsert.Error()+"\n", out)
	})
}

func Test_ListCommand(t *testing.T) {
	t.Parallel()
	t.Run("ok", func(t *testing.T) {
		mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
			store.MustParseID("foo"): pass.NewPassValue([]byte("bar")),
			store.MustParseID("baz"): pass.NewPassValue([]byte("0")),
		}))
		out, err := execute(t, ListCommand(), mock)
		assert.NoError(t, err)
		assert.Equal(t, "baz\nfoo\n", out)
	})
	t.Run("store error", func(t *testing.T) {
		errGetAll := errors.New("get error")
		mock := teststore.NewMockStore(teststore.WithStoreGetAllErr(errGetAll))
		out, err := execute(t, ListCommand(), mock)
		assert.ErrorIs(t, err, errGetAll)
		assert.Equal(t, "Error: "+errGetAll.Error()+"\n", out)
	})
}

func Test_RmCommand(t *testing.T) {
	t.Parallel()
	twoSecrets := func() store.Store {
		return teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
			store.MustParseID("foo"): pass.NewPassValue([]byte("bar")),
			store.MustParseID("baz"): pass.NewPassValue([]byte("0")),
		}))
	}
	remaining := func(t *testing.T, kc store.Store) int {
		t.Helper()
		l, err := kc.GetAllMetadata(t.Context())
		require.NoError(t, err)
		return len(l)
	}
	t.Run("ok (two secrets)", func(t *testing.T) {
		engine := &mockEngine{allow: true}
		mock := twoSecrets()
		out, err := execute(t, mustRmCommand(t, engineOpts(t, engine)...), mock, "foo", "baz")
		assert.NoError(t, err)
		assert.Equal(t, "RM: baz\nRM: foo\n", out)
		assert.Equal(t, []string{"authorize baz,foo"}, engine.recorded())
		assert.Equal(t, 0, remaining(t, mock))
	})
	t.Run("--all", func(t *testing.T) {
		engine := &mockEngine{allow: true}
		mock := twoSecrets()
		out, err := execute(t, mustRmCommand(t, engineOpts(t, engine)...), mock, "--all")
		assert.NoError(t, err)
		assert.Equal(t, "RM: baz\nRM: foo\n", out)
		assert.Equal(t, []string{"authorize baz,foo"}, engine.recorded())
		assert.Equal(t, 0, remaining(t, mock))
	})
	t.Run("denied removes nothing", func(t *testing.T) {
		engine := &mockEngine{}
		mock := twoSecrets()
		out, err := execute(t, mustRmCommand(t, engineOpts(t, engine)...), mock, "--all")
		assert.ErrorIs(t, err, client.ErrAccessDenied)
		assert.Equal(t, "Error: authorizing: access denied\n", out)
		assert.Equal(t, []string{"authorize baz,foo"}, engine.recorded())
		assert.Equal(t, 2, remaining(t, mock))
	})
	t.Run("denied reports missing secrets and removes nothing", func(t *testing.T) {
		engine := &mockEngine{}
		mock := twoSecrets()
		out, err := execute(t, mustRmCommand(t, engineOpts(t, engine)...), mock, "foo", "missing")
		assert.ErrorIs(t, err, client.ErrAccessDenied)
		assert.ErrorIs(t, err, store.ErrCredentialNotFound)
		assert.Equal(t, "ERR: missing: secret not found\nError: missing: secret not found\nauthorizing: access denied\n", out)
		assert.Equal(t, []string{"authorize foo"}, engine.recorded())
		assert.Equal(t, 2, remaining(t, mock))
	})
	t.Run("unreachable engine removes nothing", func(t *testing.T) {
		mock := twoSecrets()
		socket := deadSocket(t)
		cmd := mustRmCommand(t, WithTimeout(time.Second), WithSocketPath(socket))
		out, err := execute(t, cmd, mock, "foo")
		assert.ErrorIs(t, err, client.ErrSecretsEngineNotRunning)
		assert.Contains(t, out, "Start the secrets engine and retry: nothing is listening on "+strconv.Quote(socket)+".")
		assert.NotContains(t, out, "RM:")
		assert.Equal(t, 2, remaining(t, mock))
	})
	t.Run("store error", func(t *testing.T) {
		errRemove := errors.New("remove error")
		mock := teststore.NewMockStore(
			teststore.WithStore(map[store.ID]store.Secret{
				store.MustParseID("foo"): pass.NewPassValue([]byte("bar")),
			}),
			teststore.WithStoreDeleteErr(errRemove),
		)
		out, err := execute(t, mustRmCommand(t, engineOpts(t, &mockEngine{allow: true})...), mock, "foo")
		assert.ErrorIs(t, err, errRemove)
		assert.Equal(t, "ERR: foo: remove error\nError: "+errRemove.Error()+"\n", out)
	})
	t.Run("missing secret errors without asking the engine", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := execute(t, mustRmCommand(t, WithSocketPath(deadSocket(t))), mock, "foo")
		assert.ErrorIs(t, err, store.ErrCredentialNotFound)
		assert.Equal(t, "ERR: foo: secret not found\nError: foo: secret not found\n", out)
	})
	t.Run("missing secret among existing ones", func(t *testing.T) {
		engine := &mockEngine{allow: true}
		mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
			store.MustParseID("foo"): pass.NewPassValue([]byte("bar")),
		}))
		out, err := execute(t, mustRmCommand(t, engineOpts(t, engine)...), mock, "foo", "baz")
		assert.ErrorIs(t, err, store.ErrCredentialNotFound)
		assert.Equal(t, "ERR: baz: secret not found\nRM: foo\nError: baz: secret not found\n", out)
		assert.Equal(t, []string{"authorize foo"}, engine.recorded())
		assert.Equal(t, 0, remaining(t, mock))
	})
	t.Run("metadata listing error", func(t *testing.T) {
		errList := errors.New("list error")
		mock := teststore.NewMockStore(teststore.WithStoreGetAllErr(errList))
		out, err := execute(t, mustRmCommand(t, WithSocketPath(deadSocket(t))), mock, "foo")
		assert.ErrorIs(t, err, errList)
		assert.Equal(t, "Error: "+errList.Error()+"\n", out)
	})
	t.Run("--all with empty store needs no engine", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := execute(t, mustRmCommand(t, WithSocketPath(deadSocket(t))), mock, "--all")
		assert.NoError(t, err)
		assert.Empty(t, out)
	})
	t.Run("invalid id", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := execute(t, mustRmCommand(t), mock, "/foo")
		errInvalidID := secrets.ErrInvalidID{ID: "/foo"}
		assert.ErrorIs(t, err, errInvalidID)
		assert.Equal(t, "Error: "+errInvalidID.Error()+"\n", out)
	})
	t.Run("cannot mix --all with explicit list", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := execute(t, mustRmCommand(t), mock, "--all", "foo")
		assert.ErrorContains(t, err, "either provide a secret name or use --all to remove all secrets")
		assert.Equal(t, "Error: either provide a secret name or use --all to remove all secrets\n", out)
	})
	t.Run("no args or --all", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := execute(t, mustRmCommand(t), mock)
		assert.ErrorContains(t, err, "either provide a secret name or use --all to remove all secrets")
		assert.Equal(t, "Error: either provide a secret name or use --all to remove all secrets\n", out)
	})
	t.Run("rejects an invalid option", func(t *testing.T) {
		cmd, err := RmCommand(WithTimeout(-time.Second))
		require.EqualError(t, err, "request timeout duration cannot be negative")
		assert.Nil(t, cmd)
	})
}

func Test_GetCommand(t *testing.T) {
	t.Parallel()
	fooStore := func() store.Store {
		return teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
			store.MustParseID("foo"): pass.NewPassValue([]byte("bar")),
		}))
	}
	t.Run("ok", func(t *testing.T) {
		out, err := execute(t, mustGetCommand(t), fooStore(), "foo")
		assert.NoError(t, err)
		assert.Equal(t, "ID: foo\nValue: **********\n", out)
	})
	t.Run("store error", func(t *testing.T) {
		errGet := errors.New("get error")
		mock := teststore.NewMockStore(teststore.WithStoreGetErr(errGet))
		out, err := execute(t, mustGetCommand(t), mock, "foo")
		assert.ErrorIs(t, err, errGet)
		assert.Equal(t, "Error: "+errGet.Error()+"\n", out)
	})
	t.Run("masked output needs no engine", func(t *testing.T) {
		out, err := execute(t, mustGetCommand(t, WithSocketPath(deadSocket(t))), fooStore(), "foo")
		assert.NoError(t, err)
		assert.Equal(t, "ID: foo\nValue: **********\n", out)
	})
	t.Run("--reveal prints the value once the engine allows", func(t *testing.T) {
		engine := &mockEngine{allow: true}
		cmd := mustGetCommand(t, engineOpts(t, engine)...)
		out, err := execute(t, cmd, fooStore(), "--reveal", "foo")
		assert.NoError(t, err)
		assert.Equal(t, "ID: foo\nValue: bar\n", out)
		assert.Equal(t, []string{"authorize foo"}, engine.recorded())
	})
	t.Run("--reveal fails when the engine denies", func(t *testing.T) {
		engine := &mockEngine{}
		cmd := mustGetCommand(t, engineOpts(t, engine)...)
		out, err := execute(t, cmd, fooStore(), "--reveal", "foo")
		assert.ErrorIs(t, err, client.ErrAccessDenied)
		assert.Equal(t, "Error: authorizing: access denied\n", out)
		assert.Equal(t, []string{"authorize foo"}, engine.recorded())
	})
	t.Run("--reveal reads the keychain before asking the engine", func(t *testing.T) {
		engine := &mockEngine{allow: true}
		errGet := errors.New("get error")
		mock := teststore.NewMockStore(teststore.WithStoreGetErr(errGet))
		cmd := mustGetCommand(t, engineOpts(t, engine)...)
		out, err := execute(t, cmd, mock, "--reveal", "foo")
		assert.ErrorIs(t, err, errGet)
		assert.Equal(t, "Error: "+errGet.Error()+"\n", out)
		assert.Empty(t, engine.recorded())
	})
	t.Run("--reveal fails when the engine is unreachable", func(t *testing.T) {
		cmd := mustGetCommand(t, WithTimeout(time.Second), WithSocketPath(deadSocket(t)))
		out, err := execute(t, cmd, fooStore(), "--reveal", "foo")
		assert.ErrorIs(t, err, client.ErrSecretsEngineNotRunning)
		assert.ErrorContains(t, err, "authorizing:")
		assert.NotContains(t, out, "bar")
	})
	t.Run("--reveal pings the engine first when requests are unbounded", func(t *testing.T) {
		socket := deadSocket(t)
		cmd := mustGetCommand(t, WithSocketPath(socket))
		out, err := execute(t, cmd, fooStore(), "--reveal", "foo")
		assert.ErrorIs(t, err, client.ErrSecretsEngineNotRunning)
		assert.ErrorContains(t, err, "preflight ping")
		assert.Contains(t, out, "\n\nStart the secrets engine and retry: nothing is listening on "+strconv.Quote(socket)+".\n")
		assert.NotContains(t, out, "bar")
	})
	t.Run("rejects an invalid option", func(t *testing.T) {
		cmd, err := GetCommand(WithTimeout(-time.Second))
		require.EqualError(t, err, "request timeout duration cannot be negative")
		assert.Nil(t, cmd)
	})
}

func mustGetCommand(t *testing.T, options ...ClientOption) *cobra.Command {
	t.Helper()
	cmd, err := GetCommand(options...)
	require.NoError(t, err)
	return cmd
}

func mustRmCommand(t *testing.T, options ...ClientOption) *cobra.Command {
	t.Helper()
	cmd, err := RmCommand(options...)
	require.NoError(t, err)
	return cmd
}

func TestWithEngineHint(t *testing.T) {
	t.Parallel()
	connErr := func(reason client.ConnectReason, socket string) error {
		return fmt.Errorf("authorizing: %w", &client.ConnectError{Reason: reason, SocketPath: socket, Err: errors.New("dial")})
	}
	desktop := api.DesktopSocketPath()
	tests := []struct {
		name string
		err  error
		hint string
	}{
		{
			name: "wrapped connect error",
			err:  connErr(client.ReasonNotRunning, desktop),
			hint: "Start Docker Desktop and retry: the secrets engine runs as part of it.",
		},
		{
			name: "joined with other errors",
			err:  errors.Join(store.ErrCredentialNotFound, connErr(client.ReasonTimeout, "/s.sock")),
			hint: `The secrets engine on "/s.sock" did not respond. Restart it and retry.`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := withEngineHint(tc.err)
			assert.Equal(t, tc.err.Error()+"\n\n"+tc.hint, got.Error())
			assert.ErrorIs(t, got, tc.err)
		})
	}
	t.Run("unknown reason and other errors pass through", func(t *testing.T) {
		for _, err := range []error{nil, connErr(client.ReasonUnknown, "/s.sock"), client.ErrAccessDenied} {
			assert.Equal(t, err, withEngineHint(err))
		}
	})
}

func deadSocket(t *testing.T) string {
	t.Helper()
	return testhelper.RandomShortSocketName()
}

func engineOpts(t *testing.T, engine *mockEngine) []ClientOption {
	t.Helper()
	return []ClientOption{WithTimeout(time.Second), WithSocketPath(engine.serve(t))}
}

func execute(t *testing.T, cmd *cobra.Command, mock store.Store, args ...string) (string, error) {
	t.Helper()
	return runCobra(t, cmd, mock, nil, args)
}

func executeWithStdin(t *testing.T, cmd *cobra.Command, mock store.Store, stdin string, args ...string) (string, error) {
	t.Helper()
	return runCobra(t, cmd, mock, bytes.NewBufferString(stdin), args)
}

func runCobra(t *testing.T, cmd *cobra.Command, mock store.Store, stdin *bytes.Buffer, args []string) (string, error) {
	t.Helper()
	cmd.SilenceUsage = true
	ctx := t.Context()
	if mock != nil {
		ctx = WithStore(ctx, mock)
	}
	cmd.SetContext(ctx)
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	if stdin != nil {
		cmd.SetIn(stdin)
	}
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func assertStoredValue(t *testing.T, kc store.Store, want string) {
	t.Helper()
	s, err := kc.Get(t.Context(), secrets.MustParseID("foo"))
	require.NoError(t, err)
	impl, ok := s.(*pass.PassValue)
	require.True(t, ok)
	got, err := impl.Marshal()
	require.NoError(t, err)
	assert.Equal(t, want, string(got))
}

func assertStoredMetadata(t *testing.T, kc store.Store, want map[string]string) {
	t.Helper()
	s, err := kc.Get(t.Context(), secrets.MustParseID("foo"))
	require.NoError(t, err)
	impl, ok := s.(*pass.PassValue)
	require.True(t, ok)
	assert.Equal(t, want, impl.Metadata())
}
