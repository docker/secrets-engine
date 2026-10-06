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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client"
	pass "github.com/docker/secrets-engine/plugins/pass/store"
	"github.com/docker/secrets-engine/plugins/pass/teststore"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/keychain"
	"github.com/docker/secrets-engine/x/secrets"
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
		cmd := mustRmCommand(t, WithTimeout(time.Second), WithSocketPath(deadSocket(t)))
		out, err := execute(t, cmd, mock, "foo")
		assert.ErrorIs(t, err, client.ErrSecretsEngineNotAvailable)
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
		assert.ErrorIs(t, err, client.ErrSecretsEngineNotAvailable)
		assert.ErrorContains(t, err, "authorizing:")
		assert.NotContains(t, out, "bar")
	})
	t.Run("--reveal pings the engine first when requests are unbounded", func(t *testing.T) {
		cmd := mustGetCommand(t, WithSocketPath(deadSocket(t)))
		out, err := execute(t, cmd, fooStore(), "--reveal", "foo")
		assert.ErrorIs(t, err, client.ErrSecretsEngineNotAvailable)
		assert.ErrorContains(t, err, "preflight ping")
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

func deadSocket(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "dead.sock")
}

func engineOpts(t *testing.T, engine *mockEngine) []ClientOption {
	t.Helper()
	return []ClientOption{WithTimeout(time.Second), WithSocketPath(engine.serve(t))}
}

// execute runs cmd as if it were the root command: it attaches mock to the
// command context so RunE bodies can pull it via StoreFrom, captures stdout
// and stderr into one buffer (mirroring how cobra collapses both onto the
// user's terminal), and silences usage so error output stays minimal.
//
// Pass mock == nil for commands that do not consult the store.
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

// assertStoredValue asserts the secret stored under id "foo" — every set-test
// uses that id, so the helpers hard-code it rather than carrying a parameter
// that always receives the same string.
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

func Test_promptModel(t *testing.T) {
	t.Parallel()
	typeText := func(m promptModel, text string) promptModel {
		for _, r := range text {
			next, _ := m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
			m = next.(promptModel)
		}
		return m
	}
	press := func(m promptModel, keys ...tea.KeyPressMsg) (promptModel, tea.Cmd) {
		var cmd tea.Cmd
		for _, k := range keys {
			var next tea.Model
			next, cmd = m.Update(k)
			m = next.(promptModel)
		}
		return m, cmd
	}
	ctrl := func(r rune) tea.KeyPressMsg { return tea.KeyPressMsg{Code: r, Mod: tea.ModCtrl} }
	enter := tea.KeyPressMsg{Code: tea.KeyEnter}
	backspace := tea.KeyPressMsg{Code: tea.KeyBackspace}
	tab := tea.KeyPressMsg{Code: tea.KeyTab}

	t.Run("masks typed input", func(t *testing.T) {
		t.Parallel()
		m := typeText(newPromptModel("foo"), "hunter2")
		view := m.View().Content
		assert.Contains(t, view, "Enter secret for foo: ")
		assert.Contains(t, view, "*******")
		assert.NotContains(t, view, "hunter2")
		assert.Equal(t, "hunter2", string(m.value))
		assert.True(t, strings.HasSuffix(view, "\n"), "trailing newline keeps the line on screen at exit")
	})
	t.Run("enter submits", func(t *testing.T) {
		t.Parallel()
		m, cmd := press(typeText(newPromptModel("foo"), "hunter2"), enter)
		require.NotNil(t, cmd)
		assert.IsType(t, tea.QuitMsg{}, cmd())
		assert.NoError(t, m.err)
		assert.Equal(t, "hunter2", string(m.value))
	})
	t.Run("enter on empty input errors", func(t *testing.T) {
		t.Parallel()
		m, cmd := press(newPromptModel("foo"), enter)
		require.NotNil(t, cmd)
		assert.IsType(t, tea.QuitMsg{}, cmd())
		assert.ErrorIs(t, m.err, errEmptyValue)
	})
	t.Run("ctrl+j and ctrl+d submit like enter", func(t *testing.T) {
		t.Parallel()
		for _, k := range []tea.KeyPressMsg{ctrl('j'), ctrl('d')} {
			m, cmd := press(typeText(newPromptModel("foo"), "hunter2"), k)
			require.NotNil(t, cmd, k.String())
			assert.IsType(t, tea.QuitMsg{}, cmd(), k.String())
			assert.NoError(t, m.err, k.String())
			assert.Equal(t, "hunter2", string(m.value), k.String())
		}
	})
	t.Run("ctrl+c interrupts", func(t *testing.T) {
		t.Parallel()
		_, cmd := press(newPromptModel("foo"), ctrl('c'))
		require.NotNil(t, cmd)
		assert.IsType(t, tea.InterruptMsg{}, cmd())
	})
	t.Run("input after enter is ignored", func(t *testing.T) {
		t.Parallel()
		m, _ := press(typeText(newPromptModel("foo"), "line1"), enter)
		m = typeText(m, "line2")
		next, cmd := m.Update(tea.PasteMsg{Content: "line3"})
		assert.Nil(t, cmd)
		m = next.(promptModel)
		assert.NoError(t, m.err)
		assert.Equal(t, "line1", string(m.value))
	})
	t.Run("backspace erases one rune", func(t *testing.T) {
		t.Parallel()
		m, _ := press(typeText(newPromptModel("foo"), "héllo"), backspace, backspace, backspace)
		assert.Equal(t, "hé", string(m.value))
		m, _ = press(m, backspace, backspace, backspace)
		assert.Equal(t, "", string(m.value), "erasing past the start is a no-op")
	})
	t.Run("ctrl+w erases the last word", func(t *testing.T) {
		t.Parallel()
		m, _ := press(typeText(newPromptModel("foo"), "two words \t"), ctrl('w'))
		assert.Equal(t, "two ", string(m.value))
		m, _ = press(m, ctrl('w'), ctrl('w'))
		assert.Equal(t, "", string(m.value))
	})
	t.Run("ctrl+u clears the line", func(t *testing.T) {
		t.Parallel()
		m, _ := press(typeText(newPromptModel("foo"), "hunter2"), ctrl('u'))
		assert.Equal(t, "", string(m.value))
		assert.Equal(t, "x", string(typeText(m, "x").value), "typing continues after the kill")
	})
	t.Run("tab is stored verbatim", func(t *testing.T) {
		t.Parallel()
		m, _ := press(typeText(newPromptModel("foo"), "a"), tab)
		m = typeText(m, "b")
		assert.Equal(t, "a\tb", string(m.value))
		assert.Contains(t, m.View().Content, "***")
	})
	t.Run("ctrl+v inserts the next key literally", func(t *testing.T) {
		t.Parallel()
		m, _ := press(newPromptModel("foo"), ctrl('v'), ctrl('a'), ctrl('v'), enter, ctrl('v'), ctrl('u'))
		m = typeText(m, "x")
		assert.Equal(t, "\x01\r\x15x", string(m.value))
		assert.NoError(t, m.err)
		_, cmd := press(m, ctrl('v'), ctrl('c'))
		require.NotNil(t, cmd)
		assert.IsType(t, tea.InterruptMsg{}, cmd(), "ctrl+c always interrupts")
	})
	t.Run("keys without text are ignored", func(t *testing.T) {
		t.Parallel()
		m, _ := press(typeText(newPromptModel("foo"), "hunter2"), tea.KeyPressMsg{Code: tea.KeyUp}, tea.KeyPressMsg{Code: tea.KeyF1})
		assert.Equal(t, "hunter2", string(m.value))
	})
	t.Run("paste is stored verbatim", func(t *testing.T) {
		t.Parallel()
		next, _ := newPromptModel("foo").Update(tea.PasteMsg{Content: "a\tb\x01 \xff\n"})
		m := next.(promptModel)
		assert.NoError(t, m.err)
		assert.Equal(t, "a\tb\x01 \xff", string(m.value), "only the trailing newline is dropped")
	})
	t.Run("multi-line paste is rejected", func(t *testing.T) {
		t.Parallel()
		next, cmd := newPromptModel("foo").Update(tea.PasteMsg{Content: "line1\nline2\n"})
		require.NotNil(t, cmd)
		assert.IsType(t, tea.QuitMsg{}, cmd())
		assert.ErrorIs(t, next.(promptModel).err, errMultilinePaste)
	})
	t.Run("modifiers on enter, backspace and tab follow the tty", func(t *testing.T) {
		t.Parallel()
		shiftEnter := tea.KeyPressMsg{Code: tea.KeyEnter, Mod: tea.ModShift}
		shiftBackspace := tea.KeyPressMsg{Code: tea.KeyBackspace, Mod: tea.ModShift}
		m, cmd := press(typeText(newPromptModel("foo"), "hunter23"), shiftBackspace, shiftEnter)
		require.NotNil(t, cmd)
		assert.IsType(t, tea.QuitMsg{}, cmd())
		assert.Equal(t, "hunter2", string(m.value))
		ctrlBackspace := tea.KeyPressMsg{Code: tea.KeyBackspace, Mod: tea.ModCtrl}
		shiftTab := tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
		m, _ = press(typeText(newPromptModel("foo"), "ab"), ctrlBackspace, ctrl('i'), shiftTab)
		assert.Equal(t, "a\t", string(m.value), "ctrl+backspace erases, ctrl+i is a tab, shift+tab is ignored")
		_, cmd = press(typeText(newPromptModel("foo"), "x"), ctrl('m'))
		require.NotNil(t, cmd)
		assert.IsType(t, tea.QuitMsg{}, cmd(), "ctrl+m is CR")
		_, cmd = press(newPromptModel("foo"), tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl | tea.ModShift})
		require.NotNil(t, cmd)
		assert.IsType(t, tea.InterruptMsg{}, cmd(), "shift does not mask ctrl+c")
	})
	t.Run("a paste spends the ctrl+v quote", func(t *testing.T) {
		t.Parallel()
		m, _ := press(newPromptModel("foo"), ctrl('v'))
		next, _ := m.Update(tea.PasteMsg{Content: "ab"})
		m, cmd := press(next.(promptModel), enter)
		require.NotNil(t, cmd)
		assert.IsType(t, tea.QuitMsg{}, cmd(), "enter after the paste submits instead of inserting a literal CR")
		assert.NoError(t, m.err)
		assert.Equal(t, "ab", string(m.value))
	})
	t.Run("ctrl+v quotes every key that has bytes", func(t *testing.T) {
		t.Parallel()
		alt := func(r rune, mod tea.KeyMod) tea.KeyPressMsg { return tea.KeyPressMsg{Code: r, Mod: tea.ModAlt | mod} }
		m, _ := press(newPromptModel("foo"),
			ctrl('v'), tea.KeyPressMsg{Code: tea.KeySpace, Mod: tea.ModCtrl},
			ctrl('v'), ctrl('\\'),
			ctrl('v'), ctrl('_'),
			ctrl('v'), alt('x', 0),
			ctrl('v'), alt('x', tea.ModShift),
			ctrl('v'), alt('a', tea.ModCtrl),
			ctrl('v'), alt(tea.KeyEnter, 0),
			ctrl('v'), tea.KeyPressMsg{Code: tea.KeyUp}, tea.KeyPressMsg{Code: 'a', Text: "a"},
		)
		assert.Equal(t, "\x00\x1c\x1f\x1bx\x1bX\x1b\x01\x1b\ra", string(m.value), "an arrow has no bytes, so the quote waits for the next key")
		assert.False(t, m.literal)
	})
}

type fileWrapper struct {
	io.Reader
	f *os.File
}

func (w fileWrapper) File() (*os.File, bool) { return w.f, w.f != nil }

func Test_unwrapFile(t *testing.T) {
	t.Parallel()
	f, err := os.Open(os.DevNull)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	t.Run("plain file", func(t *testing.T) {
		t.Parallel()
		got, ok := unwrapFile(f)
		require.True(t, ok)
		assert.Same(t, f, got)
	})
	t.Run("docker stream wrapper", func(t *testing.T) {
		t.Parallel()
		got, ok := unwrapFile(fileWrapper{Reader: &bytes.Buffer{}, f: f})
		require.True(t, ok)
		assert.Same(t, f, got)
	})
	t.Run("wrapper without a file", func(t *testing.T) {
		t.Parallel()
		_, ok := unwrapFile(fileWrapper{Reader: &bytes.Buffer{}})
		assert.False(t, ok)
	})
	t.Run("buffer", func(t *testing.T) {
		t.Parallel()
		_, ok := unwrapFile(&bytes.Buffer{})
		assert.False(t, ok)
	})
}
