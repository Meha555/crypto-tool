package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

type AES struct {
	key   []byte
	block cipher.Block
	mode  interface{}
}

// TODO 假定是GCM模式

func NewAESWithKey(key []byte, mode string) (*AES, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("AES Key must be 16, 24 or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var cipherMode interface{}
	switch mode {
	case "GCM":
		cipherMode, err = cipher.NewGCM(block)
	default:
		return nil, errors.New("unsupport cipher mode: " + mode)
	}
	if err != nil {
		return nil, fmt.Errorf("create cipher mode failed: %w", err)
	}

	return &AES{
		key:   key,
		block: block,
		mode:  cipherMode,
	}, nil
}

func (a *AES) Encrypt(plainText []byte) (cipherText []byte, err error) {
	switch a.mode.(type) {
	case cipher.AEAD:
		gcm := a.mode.(cipher.AEAD)
		// 生成随机nonce
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generate nonce failed: %w", err)
		}
		cipherText = gcm.Seal(nonce, nonce, plainText, nil)
	default:
		panic("unsupport cipher mode: " + fmt.Sprintf("%T", a.mode))
	}
	return
}

func (a *AES) Decrypt(cipherText []byte) (plainText []byte, err error) {
	switch a.mode.(type) {
	case cipher.AEAD:
		gcm := a.mode.(cipher.AEAD)
		if len(cipherText) < gcm.NonceSize() {
			return nil, fmt.Errorf("cipherText too short")
		}
		var nonce []byte
		nonce, cipherText = cipherText[:gcm.NonceSize()], cipherText[gcm.NonceSize():]
		plainText, err = gcm.Open(nil, nonce, cipherText, nil)
	default:
		panic("unsupport cipher mode: " + fmt.Sprintf("%T", a.mode))
	}
	return
}
