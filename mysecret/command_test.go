package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/mysecret/service"
	"github.com/docker/secrets-engine/mysecret/teststore"
	"github.com/docker/secrets-engine/store"
)

func Test_rootCommand(t *testing.T) {
	t.Parallel()
	t.Run("set", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			mock := teststore.NewMockStore()
			out, err := executeCommand(rootCommand(t.Context(), mock), "set", "foo=bar=bar=bar")
			assert.NoError(t, err)
			assert.Empty(t, out)
			s, err := mock.Get(t.Context(), secrets.MustParseID("foo"))
			require.NoError(t, err)
			impl, ok := s.(*service.MyValue)
			require.True(t, ok)
			assert.Equal(t, "bar=bar=bar", string(impl.Value))
		})
		t.Run("from STDIN", func(t *testing.T) {
			mock := teststore.NewMockStore()
			out, err := executeCommandWithStdin(rootCommand(t.Context(), mock), "my\nmultiline\nvalue", "set", "foo")
			assert.NoError(t, err)
			assert.Empty(t, out)
			s, err := mock.Get(t.Context(), secrets.MustParseID("foo"))
			require.NoError(t, err)
			impl, ok := s.(*service.MyValue)
			require.True(t, ok)
			assert.Equal(t, "my\nmultiline\nvalue", string(impl.Value))
		})
		t.Run("store error", func(t *testing.T) {
			errSave := errors.New("save error")
			mock := teststore.NewMockStore(teststore.WithStoreSaveErr(errSave))
			out, err := executeCommand(rootCommand(t.Context(), mock), "set", "foo=bar")
			assert.ErrorIs(t, errSave, err)
			assert.Equal(t, "Error: "+errSave.Error()+"\n", out)
		})
		t.Run("invalid id", func(t *testing.T) {
			errSave := errors.New("save error")
			mock := teststore.NewMockStore(teststore.WithStoreSaveErr(errSave))
			out, err := executeCommand(rootCommand(t.Context(), mock), "set", "/foo=bar")
			errInvalidID := secrets.ErrInvalidID{ID: "/foo"}
			assert.ErrorIs(t, err, errInvalidID)
			assert.Equal(t, "Error: "+errInvalidID.Error()+"\n", out)
		})
	})
	t.Run("list", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			mock := teststore.NewMockStore(teststore.WithStore(map[string]store.Secret{
				"foo": &service.MyValue{Value: []byte("bar")},
				"baz": &service.MyValue{Value: []byte("0")},
			}))
			out, err := executeCommand(rootCommand(t.Context(), mock), "list")
			assert.NoError(t, err)
			assert.Equal(t, "baz\nfoo\n", out)
		})
		t.Run("store error", func(t *testing.T) {
			errGetAll := errors.New("get error")
			mock := teststore.NewMockStore(teststore.WithStoreGetAllErr(errGetAll))
			out, err := executeCommand(rootCommand(t.Context(), mock), "list")
			assert.ErrorIs(t, errGetAll, err)
			assert.Equal(t, "Error: "+errGetAll.Error()+"\n", out)
		})
	})
	t.Run("rm", func(t *testing.T) {
		t.Run("ok (two secrets)", func(t *testing.T) {
			mock := teststore.NewMockStore(teststore.WithStore(map[string]store.Secret{
				"foo": &service.MyValue{Value: []byte("bar")},
				"baz": &service.MyValue{Value: []byte("0")},
			}))
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm", "foo", "baz")
			assert.NoError(t, err)
			assert.Equal(t, "RM: baz\nRM: foo\n", out)
			l, err := mock.GetAllMetadata(t.Context())
			require.NoError(t, err)
			assert.Empty(t, l)
		})
		t.Run("--all", func(t *testing.T) {
			mock := teststore.NewMockStore(teststore.WithStore(map[string]store.Secret{
				"foo": &service.MyValue{Value: []byte("bar")},
				"baz": &service.MyValue{Value: []byte("0")},
			}))
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm", "--all")
			assert.NoError(t, err)
			assert.Equal(t, "RM: baz\nRM: foo\n", out)
			l, err := mock.GetAllMetadata(t.Context())
			require.NoError(t, err)
			assert.Empty(t, l)
		})
		t.Run("store error", func(t *testing.T) {
			errRemove := errors.New("remove error")
			mock := teststore.NewMockStore(teststore.WithStoreDeleteErr(errRemove))
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm", "foo")
			assert.ErrorIs(t, err, errRemove)
			assert.Equal(t, "ERR: foo: remove error\nError: "+errRemove.Error()+"\n", out)
		})
		t.Run("invalid id", func(t *testing.T) {
			mock := teststore.NewMockStore()
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm", "/foo")
			errInvalidID := secrets.ErrInvalidID{ID: "/foo"}
			assert.ErrorIs(t, err, errInvalidID)
			assert.Equal(t, "ERR: /foo: invalid ID\nError: "+errInvalidID.Error()+"\n", out)
		})
		t.Run("cannot mix --all with explicit list", func(t *testing.T) {
			mock := teststore.NewMockStore()
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm", "--all", "foo")
			assert.ErrorContains(t, err, "either provide a secret name or use --all to remove all secrets")
			assert.Equal(t, "Error: either provide a secret name or use --all to remove all secrets\n", out)
		})
		t.Run("no args or --all", func(t *testing.T) {
			mock := teststore.NewMockStore()
			out, err := executeCommand(rootCommand(t.Context(), mock), "rm")
			assert.ErrorContains(t, err, "either provide a secret name or use --all to remove all secrets")
			assert.Equal(t, "Error: either provide a secret name or use --all to remove all secrets\n", out)
		})
	})
	t.Run("get", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			mock := teststore.NewMockStore(teststore.WithStore(map[string]store.Secret{
				"foo": &service.MyValue{Value: []byte("bar")},
			}))
			out, err := executeCommand(rootCommand(t.Context(), mock), "get", "foo")
			assert.NoError(t, err)
			assert.Equal(t, "ID: foo\nValue: bar\n", out)
		})
		t.Run("store error", func(t *testing.T) {
			errGet := errors.New("get error")
			mock := teststore.NewMockStore(teststore.WithStoreGetErr(errGet))
			out, err := executeCommand(rootCommand(t.Context(), mock), "get", "foo")
			assert.ErrorIs(t, err, errGet)
			assert.Equal(t, "Error: "+errGet.Error()+"\n", out)
		})
	})
}

func executeCommandWithStdin(root *cobra.Command, stdin string, args ...string) (output string, err error) {
	inBuf := bytes.NewBufferString(stdin)
	buf := &bytes.Buffer{}
	root.SetIn(inBuf)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	err = root.Execute()

	return buf.String(), err
}

func executeCommand(root *cobra.Command, args ...string) (output string, err error) {
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	err = root.Execute()

	return buf.String(), err
}
