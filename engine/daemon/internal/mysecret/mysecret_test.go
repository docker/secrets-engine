package mysecret

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/mysecret/service"
	"github.com/docker/secrets-engine/mysecret/teststore"
	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

func Test_mysecretPlugin(t *testing.T) {
	t.Parallel()
	t.Run("ok", func(t *testing.T) {
		mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
			store.MustParseID("foo"): &service.MyValue{Value: []byte("bar")},
		}))
		p := &mysecretPlugin{kc: mock, logger: testhelper.TestLogger(t)}
		e, err := p.GetSecrets(t.Context(), secrets.Request{Pattern: secrets.MustParsePattern("foo")})
		require.NoError(t, err)
		require.NotEmpty(t, e)
		assert.Equal(t, "bar", string(e[0].Value))
	})
	t.Run("no secrets", func(t *testing.T) {
		mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{}))
		p := &mysecretPlugin{kc: mock}
		_, err := p.GetSecrets(t.Context(), secrets.Request{Pattern: secrets.MustParsePattern("foo")})
		assert.ErrorIs(t, err, secrets.ErrNotFound)
	})
	t.Run("store error", func(t *testing.T) {
		errFilter := errors.New("filter error")
		mock := teststore.NewMockStore(teststore.WithStoreFilterErr(errFilter))
		p := &mysecretPlugin{kc: mock, logger: testhelper.TestLogger(t)}
		_, err := p.GetSecrets(t.Context(), secrets.Request{Pattern: secrets.MustParsePattern("foo")})
		assert.ErrorIs(t, err, errFilter)
	})
	t.Run("unwrap error", func(*testing.T) {
		// TODO
	})
}
