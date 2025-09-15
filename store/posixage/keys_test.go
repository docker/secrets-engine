package posixage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

type unknownFunc keyCallbackFunc

func (u unknownFunc) call(ctx context.Context) ([]byte, error) {
	return u(ctx)
}

func TestGroupCallbackFuncs(t *testing.T) {
	tests := []struct {
		desc   string
		funcs  []callbackFunc
		expect func(t *testing.T, g map[keyType][]string, err error)
	}{
		{
			desc: "order inside of a group is preserved",
			funcs: []callbackFunc{
				DecryptionAgeX25519(func(_ context.Context) ([]byte, error) {
					return []byte("age"), nil
				}),
				DecryptionSSH(func(_ context.Context) ([]byte, error) {
					return []byte("ssh-1"), nil
				}),
				DecryptionSSH(func(_ context.Context) ([]byte, error) {
					return []byte("ssh-2"), nil
				}),
				DecryptionPassword(func(_ context.Context) ([]byte, error) {
					return []byte("password"), nil
				}),
			},
			expect: func(t *testing.T, g map[keyType][]string, err error) {
				t.Helper()
				assert.NoError(t, err)
				assert.Len(t, g, 3)
				assert.Len(t, g[sshKeyType], 2)
				assert.Equal(t, []string{"ssh-1", "ssh-2"}, g[sshKeyType])
			},
		},
		{
			desc: "unknown functions will cause an error",
			funcs: []callbackFunc{
				unknownFunc(func(_ context.Context) ([]byte, error) {
					return nil, nil
				}),
			},
			expect: func(t *testing.T, _ map[keyType][]string, err error) {
				t.Helper()
				assert.ErrorContains(t, err, "invalid callback function type")
			},
		},
		{
			desc: "empty key returned will cause an error",
			funcs: []callbackFunc{
				DecryptionPassword(func(_ context.Context) ([]byte, error) {
					return []byte{}, nil
				}),
			},
			expect: func(t *testing.T, _ map[keyType][]string, err error) {
				t.Helper()
				assert.ErrorContains(t, err, "empty key provided on registered callback function")
			},
		},
		{
			desc: "unordered functions will still be grouped in order",
			funcs: []callbackFunc{
				DecryptionPassword(func(_ context.Context) ([]byte, error) {
					return []byte("pass-1"), nil
				}),
				DecryptionSSH(func(_ context.Context) ([]byte, error) {
					return []byte("ssh-1"), nil
				}),
				DecryptionPassword(func(_ context.Context) ([]byte, error) {
					return []byte("pass-2"), nil
				}),
				DecryptionAgeX25519(func(_ context.Context) ([]byte, error) {
					return []byte("age-1"), nil
				}),
				DecryptionAgeX25519(func(_ context.Context) ([]byte, error) {
					return []byte("age-2"), nil
				}),
				DecryptionPassword(func(_ context.Context) ([]byte, error) {
					return []byte("pass-3"), nil
				}),
			},
			expect: func(t *testing.T, g map[keyType][]string, err error) {
				t.Helper()
				assert.NoError(t, err)
				assert.Len(t, g, 3)
				assert.Len(t, g[passwordKeyType], 3)
				assert.Len(t, g[ageKeyType], 2)
				assert.Len(t, g[sshKeyType], 1)
				assert.Equal(t, []string{"pass-1", "pass-2", "pass-3"}, g[passwordKeyType])
				assert.Equal(t, []string{"age-1", "age-2"}, g[ageKeyType])
				assert.Equal(t, []string{"ssh-1"}, g[sshKeyType])
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			groups, err := groupCallbackFuncs(t.Context(), tc.funcs)
			tc.expect(t, groups, err)
		})
	}
}
