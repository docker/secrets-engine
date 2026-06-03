package secretservice

import (
	"crypto/sha256"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestNewKeypair(t *testing.T) {
	group := rfc2409SecondOakleyGroup()
	private, public, err := group.NewKeypair()
	require.NoError(t, err)
	require.NotNil(t, private)
	require.NotNil(t, public)
	private2, public2, err := group.NewKeypair()
	require.NoError(t, err)
	require.NotEqual(t, private.Cmp(private2), 0, "should get different private key with every keygen")
	require.NotEqual(t, public.Cmp(public2), 0, "should get different public key with every keygen")
}

func TestKeygen(t *testing.T) {
	group := rfc2409SecondOakleyGroup()
	myPrivate, myPublic, err := group.NewKeypair()
	require.NoError(t, err)
	theirPrivate, theirPublic, err := group.NewKeypair()
	require.NoError(t, err)

	myKey, err := group.keygenHKDFSHA256AES128(theirPublic, myPrivate)
	require.NoError(t, err)
	theirKey, err := group.keygenHKDFSHA256AES128(myPublic, theirPrivate)
	require.NoError(t, err)
	require.Equal(t, myKey, theirKey)
}

// TestKeygenPadsSharedSecretWithLeadingZero is a regression test for the
// intermittent "secret was transferred or encrypted in an invalid way" failure.
// The Secret Service peer derives the AES key over the DH shared secret encoded
// as a fixed-length 128-byte big-endian value; big.Int.Bytes() drops leading
// zero bytes, so a shared secret with a leading zero byte (~1/256 of sessions)
// used to yield a shorter HKDF input and a mismatched key.
//
// Using myPrivate = 1 makes the shared secret equal to theirPublic (theirPublic^1
// mod p), and 2^1016-1 is only 127 bytes wide, so its group encoding has a
// leading zero byte. The derived key must match HKDF over the zero-padded
// 128-byte encoding, not the stripped 127-byte one.
func TestKeygenPadsSharedSecretWithLeadingZero(t *testing.T) {
	group := rfc2409SecondOakleyGroup()

	theirPublic := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 1016), big.NewInt(1))
	require.Len(t, theirPublic.Bytes(), 127, "test vector must have a leading zero byte in its 128-byte encoding")

	got, err := group.keygenHKDFSHA256AES128(theirPublic, big.NewInt(1))
	require.NoError(t, err)

	primeLen := (group.p.BitLen() + 7) / 8
	require.Equal(t, 128, primeLen)
	padded := make([]byte, primeLen)
	theirPublic.FillBytes(padded)

	require.Equal(t, hkdfAESKey(t, padded), got, "key must derive from the zero-padded shared secret")
	require.NotEqual(t, hkdfAESKey(t, theirPublic.Bytes()), got, "stripped-leading-zero encoding must derive a different (wrong) key")
}

// hkdfAESKey derives a 16-byte AES key from ikm the same way
// keygenHKDFSHA256AES128 does, so tests can assert against the expected input.
func hkdfAESKey(t *testing.T, ikm []byte) []byte {
	t.Helper()
	r := hkdf.New(sha256.New, ikm, nil, nil)
	key := make([]byte, 16)
	_, err := io.ReadFull(r, key)
	require.NoError(t, err)
	return key
}

func TestEncryption(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plaintext := []byte("hello world")
	iv, ciphertext, err := unauthenticatedAESCBCEncrypt(plaintext, key)
	require.NoError(t, err)
	gotPlaintext, err := unauthenticatedAESCBCDecrypt(iv, ciphertext, key)
	require.NoError(t, err)
	require.Equal(t, plaintext, gotPlaintext)
}

func TestEncryptionRng(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plaintext := []byte("hello world")
	iv1, ciphertext1, err := unauthenticatedAESCBCEncrypt(plaintext, key)
	require.NoError(t, err)
	iv2, ciphertext2, err := unauthenticatedAESCBCEncrypt(plaintext, key)
	require.NoError(t, err)
	require.NotEqual(t, iv1, iv2)
	require.NotEqual(t, ciphertext1, ciphertext2)
}

var pkcs7tests = []struct {
	in  []byte
	out []byte
}{
	{[]byte{}, []byte{4, 4, 4, 4}},
	{[]byte{1, 2}, []byte{1, 2, 2, 2}},
	{[]byte{1, 2, 3}, []byte{1, 2, 3, 1}},
	{[]byte{1, 2, 3, 4}, []byte{1, 2, 3, 4, 4, 4, 4, 4}},
	{[]byte{1, 2, 3, 4, 5}, []byte{1, 2, 3, 4, 5, 3, 3, 3}},
	{[]byte{1, 2, 3, 4, 1, 1, 1}, []byte{1, 2, 3, 4, 1, 1, 1, 1}},
}

func TestPKCS7(t *testing.T) {
	for _, testCase := range pkcs7tests {
		require.Equal(t, padPKCS7(testCase.in, 4), testCase.out)
		preimage, err := unpadPKCS7(testCase.out, 4)
		require.NoError(t, err)
		require.Equal(t, preimage, testCase.in)
	}

	_, err := unpadPKCS7([]byte{}, 4)
	require.Error(t, err)
	_, err = unpadPKCS7([]byte{1, 2, 3, 4}, 4)
	require.Error(t, err)
	_, err = unpadPKCS7([]byte{1, 2, 3, 3}, 4)
	require.Error(t, err)
	_, err = unpadPKCS7([]byte{1, 2, 3, 4, 1, 1, 1, 2}, 4)
	require.Error(t, err)
}
