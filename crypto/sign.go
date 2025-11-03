package crypto

import (
	"bytes"
)

func Sign(hashAlgorithm string, encryptAlgorithm string, input []byte, key *Key) (signature []byte, err error) {
	// hash
	hash, err := Hash(hashAlgorithm, input, nil)
	if err != nil {
		return
	}

	// encrypt
	signature, err = Encrypt(encryptAlgorithm, hash, key)
	if err != nil {
		return
	}

	return
}

func Verify(hashAlgorithm string, decryptAlgorithm string, input []byte, signature []byte, key *Key) (success bool, err error) {
	// decrypt signature to get hash
	decryptedHash, err := Decrypt(decryptAlgorithm, signature, key)
	if err != nil {
		return false, err
	}

	inputHash, err := Hash(hashAlgorithm, input, nil)
	if err != nil {
		return false, err
	}

	// compare hashes
	success = bytes.Equal(decryptedHash, inputHash)
	return
}
