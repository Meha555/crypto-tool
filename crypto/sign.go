package crypto

func Sign(hashAlgorithm string, encryptAlgorithm string, input []byte, key []byte, salt []byte) (signature []byte, err error) {
	// hash
	hash, err := Hash(hashAlgorithm, input, salt)
	if err != nil {
		return
	}
	// encrypt
	signature, err = Encrypt(encryptAlgorithm, hash, key)
	return
}

func Verify(hashAlgorithm string, decryptAlgorithm string, signature []byte, key []byte, salt []byte) (success bool, err error) {
	// decrypt
	plaintext, err := Decrypt(decryptAlgorithm, signature, key)
	if err != nil {
		return
	}
	// sign

	// compare
}