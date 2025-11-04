package crypto

import (
	"crypto"
	"fmt"
	"strings"
)

const (
	HashMD5    = "md5"
	HashSHA1   = "sha1"
	HashSHA256 = "sha256"
	HashSHA512 = "sha512"
)

func toHash(hashAlgorithm string) (crypto.Hash, error) {
	switch strings.ToLower(hashAlgorithm) {
	case HashMD5:
		return crypto.MD5, nil
	case HashSHA1:
		return crypto.SHA1, nil
	case HashSHA256:
		return crypto.SHA256, nil
	case HashSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %s", hashAlgorithm)
	}
}

const (
	CryptoAES = "aes"
	CryptoRSA = "rsa"
)

const (
	RSAPaddingPKCS1 = "pkcs1"
	RSAPaddingOAEP  = "oaep"
	RSAPaddingNone  = "none"
)
