package crypto

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"strings"
)

type Encrypter interface {
	Encrypt(plainText []byte) (cipherText []byte, err error)
}

type Decrypter interface {
	Decrypt(cipherText []byte) (plainText []byte, err error)
}

type Signer interface {
	Sign(digest []byte, hash crypto.Hash) (signature []byte, err error)
}

type Verifier interface {
	Verify(digest []byte, signature []byte, hash crypto.Hash) (bool, error)
}

// 生成随机盐值
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// 生成指定长度的随机密钥（单位：字节）
func GenerateKey(length int) (*Key, error) {
	key := make([]byte, length)
	// 使用crypto/rand生成加密安全的随机密钥
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("generate random key failed: %w", err)
	}
	return &Key{key}, nil
}

func Encrypt(algorithm string, plainText []byte, key *Key) (cipherText []byte, err error) {
	var encrypter Encrypter
	switch strings.ToLower(algorithm) {
	case CryptoAES:
		encrypter, err = NewAESWithKey(key, "GCM")
	case CryptoRSA:
		// 尝试将key解析为RSA公钥
		var rsaPubKey *RSAPublicKey
		rsaPubKey, err = DecodeToRSAPublicKey(key.Key())
		if err != nil {
			return nil, err
		}
		encrypter = NewRSAWithPublicKey(rsaPubKey.PubKey())
	default:
		err = fmt.Errorf("encrypt algorithm %s not supported", algorithm)
	}
	if err != nil {
		return
	}

	cipherText, err = encrypter.Encrypt(plainText)
	return
}

func Decrypt(algorithm string, cipherText []byte, key *Key) (plainText []byte, err error) {
	var decrypter Decrypter
	switch strings.ToLower(algorithm) {
	case CryptoAES:
		decrypter, err = NewAESWithKey(key, "GCM")
	case CryptoRSA:
		// 尝试将key解析为RSA私钥
		var rsaPrivKey *RSAPrivateKey
		rsaPrivKey, err = DecodeToRSAPrivateKey(key.Key())
		if err != nil {
			return nil, err
		}
		decrypter = NewRSAWithPrivateKey(rsaPrivKey.PriKey())
	default:
		err = fmt.Errorf("decrypt algorithm %s not supported", algorithm)
	}
	if err != nil {
		return
	}

	plainText, err = decrypter.Decrypt(cipherText)
	return
}
