package pass

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/docker/secrets-engine/plugins/pass/commands"
	pass "github.com/docker/secrets-engine/plugins/pass/store"
	"github.com/docker/secrets-engine/plugins/pass/teststore"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

var mockInfo = commands.VersionInfo{
	Version: "v88",
	Commit:  "abc",
}

func Test_rootCommand(t *testing.T) {
	t.Parallel()
	t.Run("version", func(t *testing.T) {
		mock := teststore.NewMockStore()
		out, err := executeCommand(Root(t.Context(), mock, mockInfo), "version")
		assert.NoError(t, err)
		assert.Equal(t, "Version: v88\nCommit: abc\n", out)
	})
	t.Run("set", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			mock := teststore.NewMockStore()
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "set", "foo=bar=bar=bar")
			assert.NoError(t, err)
			assert.Empty(t, out)
			s, err := mock.Get(t.Context(), secrets.MustParseID("foo"))
			require.NoError(t, err)
			impl, ok := s.(*pass.PassValue)
			require.True(t, ok)
			assert.Equal(t, "bar=bar=bar", string(impl.Value))
		})
		t.Run("from STDIN", func(t *testing.T) {
			mock := teststore.NewMockStore()
			out, err := executeCommandWithStdin(Root(t.Context(), mock, mockInfo), "my\nmultiline\nvalue", "set", "foo")
			assert.NoError(t, err)
			assert.Empty(t, out)
			s, err := mock.Get(t.Context(), secrets.MustParseID("foo"))
			require.NoError(t, err)
			impl, ok := s.(*pass.PassValue)
			require.True(t, ok)
			assert.Equal(t, "my\nmultiline\nvalue", string(impl.Value))
		})
		t.Run("store error", func(t *testing.T) {
			errSave := errors.New("save error")
			mock := teststore.NewMockStore(teststore.WithStoreSaveErr(errSave))
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "set", "foo=bar")
			assert.ErrorIs(t, errSave, err)
			assert.Equal(t, "Error: "+errSave.Error()+"\n", out)
		})
		t.Run("invalid id", func(t *testing.T) {
			errSave := errors.New("save error")
			mock := teststore.NewMockStore(teststore.WithStoreSaveErr(errSave))
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "set", "/foo=bar")
			errInvalidID := secrets.ErrInvalidID{ID: "/foo"}
			assert.ErrorIs(t, err, errInvalidID)
			assert.Equal(t, "Error: "+errInvalidID.Error()+"\n", out)
		})
	})
	t.Run("list", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
				store.MustParseID("foo"): &pass.PassValue{Value: []byte("bar")},
				store.MustParseID("baz"): &pass.PassValue{Value: []byte("0")},
			}))
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "list")
			assert.NoError(t, err)
			assert.Equal(t, "baz\nfoo\n", out)
		})
		t.Run("store error", func(t *testing.T) {
			errGetAll := errors.New("get error")
			mock := teststore.NewMockStore(teststore.WithStoreGetAllErr(errGetAll))
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "list")
			assert.ErrorIs(t, errGetAll, err)
			assert.Equal(t, "Error: "+errGetAll.Error()+"\n", out)
		})
	})
	t.Run("rm", func(t *testing.T) {
		t.Run("ok (two secrets)", func(t *testing.T) {
			mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
				store.MustParseID("foo"): &pass.PassValue{Value: []byte("bar")},
				store.MustParseID("baz"): &pass.PassValue{Value: []byte("0")},
			}))
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "rm", "foo", "baz")
			assert.NoError(t, err)
			assert.Equal(t, "RM: baz\nRM: foo\n", out)
			l, err := mock.GetAllMetadata(t.Context())
			require.NoError(t, err)
			assert.Empty(t, l)
		})
		t.Run("--all", func(t *testing.T) {
			mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
				store.MustParseID("foo"): &pass.PassValue{Value: []byte("bar")},
				store.MustParseID("baz"): &pass.PassValue{Value: []byte("0")},
			}))
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "rm", "--all")
			assert.NoError(t, err)
			assert.Equal(t, "RM: baz\nRM: foo\n", out)
			l, err := mock.GetAllMetadata(t.Context())
			require.NoError(t, err)
			assert.Empty(t, l)
		})
		t.Run("store error", func(t *testing.T) {
			errRemove := errors.New("remove error")
			mock := teststore.NewMockStore(teststore.WithStoreDeleteErr(errRemove))
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "rm", "foo")
			assert.ErrorIs(t, err, errRemove)
			assert.Equal(t, "ERR: foo: remove error\nError: "+errRemove.Error()+"\n", out)
		})
		t.Run("invalid id", func(t *testing.T) {
			mock := teststore.NewMockStore()
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "rm", "/foo")
			errInvalidID := secrets.ErrInvalidID{ID: "/foo"}
			assert.ErrorIs(t, err, errInvalidID)
			assert.Equal(t, "Error: "+errInvalidID.Error()+"\n", out)
		})
		t.Run("cannot mix --all with explicit list", func(t *testing.T) {
			mock := teststore.NewMockStore()
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "rm", "--all", "foo")
			assert.ErrorContains(t, err, "either provide a secret name or use --all to remove all secrets")
			assert.Equal(t, "Error: either provide a secret name or use --all to remove all secrets\n", out)
		})
		t.Run("no args or --all", func(t *testing.T) {
			mock := teststore.NewMockStore()
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "rm")
			assert.ErrorContains(t, err, "either provide a secret name or use --all to remove all secrets")
			assert.Equal(t, "Error: either provide a secret name or use --all to remove all secrets\n", out)
		})
	})
	t.Run("get", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
				store.MustParseID("foo"): &pass.PassValue{Value: []byte("bar")},
			}))
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "get", "foo")
			assert.NoError(t, err)
			assert.Equal(t, "ID: foo\nValue: **********\n", out)
		})
		t.Run("store error", func(t *testing.T) {
			errGet := errors.New("get error")
			mock := teststore.NewMockStore(teststore.WithStoreGetErr(errGet))
			out, err := executeCommand(Root(t.Context(), mock, mockInfo), "get", "foo")
			assert.ErrorIs(t, err, errGet)
			assert.Equal(t, "Error: "+errGet.Error()+"\n", out)
		})
	})
}

func Test_rootCommandTelemetry(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "set",
			args: []string{"set", "foo=bar"},
		},
		{
			name: "get",
			args: []string{"get", "baz"},
		},
		{
			name: "ls",
			args: []string{"list"},
		},
		{
			name: "rm",
			args: []string{"delete", "baz"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spanRecorder, metricReader := testhelper.SetupTelemetry(t)
			mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
				store.MustParseID("baz"): &pass.PassValue{Value: []byte("bar")},
			}))
			_, err := executeCommand(Root(t.Context(), mock, mockInfo), tc.args...)
			assert.NoError(t, err)

			var rm metricdata.ResourceMetrics
			err = metricReader.Collect(t.Context(), &rm)
			require.NoError(t, err)

			totalMetrics := testhelper.FilterMetrics(rm, "secrets.pass.called")
			require.Len(t, totalMetrics, 1)
			assert.Equal(t, int64(1), totalMetrics[0].Data.(metricdata.Sum[int64]).DataPoints[0].Value)
			data, ok := totalMetrics[0].Data.(metricdata.Sum[int64]).DataPoints[0].Attributes.Value("command")
			require.True(t, ok)
			assert.Equal(t, tc.name, data.AsString())

			spans := spanRecorder.Ended()
			require.Len(t, spans, 1)
			recordedSpan := spans[0]
			assert.Equal(t, "secrets.pass.called", recordedSpan.Name())
			require.Len(t, recordedSpan.Attributes(), 1)
			assert.Equal(t, tc.name, recordedSpan.Attributes()[0].Value.AsString())
			assert.Equal(t, codes.Ok, recordedSpan.Status().Code)
		})
	}
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
