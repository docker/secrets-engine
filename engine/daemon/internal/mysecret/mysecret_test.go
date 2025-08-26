package mysecret

import (
	"bytes"
	"encoding/binary"
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
		e, err := p.GetSecrets(t.Context(), secrets.MustParsePattern("foo"))
		require.NoError(t, err)
		require.NotEmpty(t, e)
		assert.Equal(t, "bar", string(e[0].Value))
	})
	t.Run("no secrets", func(t *testing.T) {
		mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{}))
		p := &mysecretPlugin{kc: mock}
		_, err := p.GetSecrets(t.Context(), secrets.MustParsePattern("foo"))
		assert.ErrorIs(t, err, secrets.ErrNotFound)
	})
	t.Run("store error", func(t *testing.T) {
		errFilter := errors.New("filter error")
		mock := teststore.NewMockStore(teststore.WithStoreFilterErr(errFilter))
		p := &mysecretPlugin{kc: mock, logger: testhelper.TestLogger(t)}
		_, err := p.GetSecrets(t.Context(), secrets.MustParsePattern("foo"))
		assert.ErrorIs(t, err, errFilter)
	})
	t.Run("unwrap error", func(*testing.T) {
		mock := teststore.NewMockStore(teststore.WithStore(map[store.ID]store.Secret{
			store.MustParseID("foo"): &MockMyOtherValue{Value: 7},
		}))
		p := &mysecretPlugin{kc: mock, logger: testhelper.TestLogger(t)}
		_, err := p.GetSecrets(t.Context(), secrets.MustParsePattern("foo"))
		assert.ErrorIs(t, err, secrets.ErrNotFound)
	})
}

var _ store.Secret = &MockMyOtherValue{}

type MockMyOtherValue struct {
	Value int64 `json:"value"`
}

func (m *MockMyOtherValue) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, m.Value); err != nil {
		return nil, err
	}
	data := buf.Bytes()
	return data, nil
}

func (m *MockMyOtherValue) Unmarshal(data []byte) error {
	var decoded int64
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &decoded); err != nil {
		return err
	}
	m.Value = decoded
	return nil
}

func (m *MockMyOtherValue) Metadata() map[string]string {
	return nil
}

func (m *MockMyOtherValue) SetMetadata(map[string]string) error {
	return nil
}
