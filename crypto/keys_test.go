package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	var (
		privKey = GeneratePrivateKey()
		pubKey  = privKey.Public()
	)
	// generate privatekey and size should be 64
	assert.Equal(t, len(privKey.Bytes()), priKeyLen)

	// generate public and test size should be 32
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestPrivateKeySign(t *testing.T) {
	var (
		privKey        = GeneratePrivateKey()
		pubKey         = privKey.Public()
		msg            = []byte("kasetsart university")
		sig            = privKey.Sign(msg)
		wrongMsg       = []byte("wrong message")
		invalidPrivKey = GeneratePrivateKey()
		invalidPubKey  = invalidPrivKey.Public()
	)

	// test with valid message
	assert.True(t, sig.Verify(pubKey, msg))

	// test with invalid message
	assert.False(t, sig.Verify(pubKey, wrongMsg))

	// //test with invalid public key
	assert.False(t, sig.Verify(invalidPubKey, msg))
}

func TestPublicKeyToAddress(t *testing.T) {
	var (
		priKey  = GeneratePrivateKey()
		pubKey  = priKey.Public()
		address = pubKey.Address()
	)

	assert.Equal(t, addressLen, len(address.value))
}

func TestNewPrivateKeyFromString(t *testing.T) {
	var (
		seed    = "b13a5d8eaab8c1d4a6bd21a5ebb391be3e79021a94e05005f4db1e2981bb8949"
		priKey  = NewPrivateKeyFromString(seed)
		address = priKey.Public().Address()
	)

	assert.Equal(t, priKeyLen, len(priKey.Bytes()))
	assert.Equal(t, len(address.Bytes()), addressLen)
}
