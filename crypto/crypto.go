package crypto

import (
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
		return nil, fmt.Errorf("生成密钥失败: %v", err)
	}
	return &Key{key}, nil
}

func Encrypt(algorithm string, plainText []byte, key *Key) (cipherText []byte, err error) {
	var encrypter Encrypter
	switch strings.ToLower(algorithm) {
	case "aes":
		encrypter, err = NewAESWithKey(key, "GCM")
	default:
		err = fmt.Errorf("加密算法 %s 不支持", algorithm)
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
	case "aes":
		decrypter, err = NewAESWithKey(key, "GCM")
	default:
		err = fmt.Errorf("解密算法 %s 不支持", algorithm)
	}
	if err != nil {
		return
	}
	plainText, err = decrypter.Decrypt(cipherText)
	return
}
