package crypto

import (
	"crypto/cipher"
)

type RSA struct {
	pubKey  *Key
	privKey *Key
	block   cipher.Block
}

// func GenerateRSAKeyPair(bits int) (pubKey *Key, privKey *Key, err error) {
// 	var priK *rsa.PrivateKey
// 	priK, err = rsa.GenerateKey(rand.Reader, bits)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
// 	}
// 	derStream,
// }
