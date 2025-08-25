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
)

func Test_mysecretPlugin(t *testing.T) {
	t.Parallel()
	t.Run("ok", func(t *testing.T) {
		mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
			store.MustParseID("foo"): &service.MyValue{Value: []byte("bar")},
		}))
		p := &mysecretPlugin{kc: mock}
		e, err := p.GetSecret(t.Context(), secrets.Request{ID: secrets.MustParseID("foo")})
		require.NoError(t, err)
		assert.Equal(t, "bar", string(e.Value))
	})
	t.Run("store error", func(t *testing.T) {
		errGet := errors.New("get error")
		mock := teststore.NewMockStore(teststore.WithStoreGetErr(errGet))
		p := &mysecretPlugin{kc: mock}
		e, err := p.GetSecret(t.Context(), secrets.Request{ID: secrets.MustParseID("foo")})
		assert.ErrorIs(t, err, errGet)
		assert.Equal(t, errGet.Error(), e.Error)
	})
}
