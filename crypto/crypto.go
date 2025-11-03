package crypto

import (
	"crypto/rand"
	"fmt"
)

type Encrypter interface {
	Encrypt(plainText []byte) (cipherText []byte, err error)
}

type Decrypter interface {
	Decrypt(cipherText []byte) (plainText []byte, err error)
}

// 生成指定长度的随机密钥（单位：字节）
func GenerateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	// 使用crypto/rand生成加密安全的随机密钥
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("生成密钥失败: %v", err)
	}
	return key, nil
}

func Encrypt(algorithm string, plainText []byte, key []byte) (cipherText []byte, err error) {
	var encrypter Encrypter
	switch algorithm {
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

func Decrypt(algorithm string, cipherText []byte, key []byte) (plainText []byte, err error) {
	var decrypter Decrypter
	switch algorithm {
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
