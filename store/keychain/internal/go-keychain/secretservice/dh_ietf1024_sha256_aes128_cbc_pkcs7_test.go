package secretservice

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
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

func TestEncodePadsLeadingZero(t *testing.T) {
	group := rfc2409SecondOakleyGroup()

	public := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 1016), big.NewInt(1))
	require.Len(t, public.Bytes(), 127)

	got := group.encode(public)
	require.Len(t, got, 128)
	require.Equal(t, byte(0), got[0])
	require.Equal(t, public.Bytes(), got[1:])
	require.Equal(t, 0, public.Cmp(new(big.Int).SetBytes(got)))
}

func FuzzEncode(f *testing.F) {
	group := rfc2409SecondOakleyGroup()
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{2})
	f.Add(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 1016), big.NewInt(1)).Bytes())
	f.Add(group.pMinus1.Bytes())
	f.Add(bytes.Repeat([]byte{0xff}, 128))
	f.Fuzz(func(t *testing.T, raw []byte) {
		v := new(big.Int).Mod(new(big.Int).SetBytes(raw), group.p)
		got := group.encode(v)
		require.Len(t, got, 128)
		require.Equal(t, 0, v.Cmp(new(big.Int).SetBytes(got)))
		minimal := v.Bytes()
		pad := len(got) - len(minimal)
		require.Equal(t, make([]byte, pad), got[:pad])
		require.Equal(t, minimal, got[pad:])
	})
}

func FuzzDHExchange(f *testing.F) {
	group := rfc2409SecondOakleyGroup()
	//nolint:lll
	privateWithShortPublic, _ := new(big.Int).SetString("6d32ef111c81963d9b32ba129a6df82d3fe4cfeac67943bf828185e6cb74c8af1bbbb92bceb188e6a3d3b09bff44aefac0ad5fd1957a87c4e94e29dae935b0878c1bf509c40b60deedb4621a710ae24d012479795556b82bb9827ed8a4cf6365d7931307e07e7bb3adf7f1f1aca78d0149f79e45630ee0fe1a9dc29f91596992", 16)
	f.Add([]byte{1}, []byte{2})
	f.Add(privateWithShortPublic.Bytes(), []byte{1})
	f.Add([]byte{1}, privateWithShortPublic.Bytes())
	f.Add(privateWithShortPublic.Bytes(), new(big.Int).Sub(group.pMinus1, bigOne).Bytes())
	f.Fuzz(func(t *testing.T, ourRaw, theirRaw []byte) {
		ourPrivate, ourPublic := fuzzKeypair(t, group, ourRaw)
		theirPrivate, theirPublic := fuzzKeypair(t, group, theirRaw)

		ourWire := group.encode(ourPublic)
		theirWire := group.encode(theirPublic)
		require.Len(t, ourWire, 128)
		require.Len(t, theirWire, 128)

		ourKey, err := group.keygenHKDFSHA256AES128(new(big.Int).SetBytes(theirWire), ourPrivate)
		require.NoError(t, err)
		theirKey, err := group.keygenHKDFSHA256AES128(new(big.Int).SetBytes(ourWire), theirPrivate)
		require.NoError(t, err)
		require.Equal(t, ourKey, theirKey)
	})
}

func fuzzKeypair(t *testing.T, group *dhGroup, raw []byte) (private, public *big.Int) {
	t.Helper()
	private = new(big.Int).Mod(new(big.Int).SetBytes(raw), group.pMinus1)
	if private.Sign() == 0 {
		t.Skip("private key must be positive")
	}
	public = new(big.Int).Exp(group.g, private, group.p)
	if public.Cmp(bigOne) <= 0 || public.Cmp(group.pMinus1) >= 0 {
		t.Skip("degenerate public key")
	}
	return private, public
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
	key, err := hkdf.Key(sha256.New, ikm, nil, "", 16)
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
