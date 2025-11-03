package crypto

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

type AES struct {
	key   *Key
	block cipher.Block
	mode  interface{}
}

// TODO 假定是GCM模式

func NewAESWithKey(key *Key, mode string) (*AES, error) {
	if key.Len() != 16 && key.Len() != 24 && key.Len() != 32 {
		return nil, fmt.Errorf("AES Key must be 16, 24 or 32 bytes")
	}
	block, err := aes.NewCipher(key.Key())
	if err != nil {
		return nil, err
	}

	var cipherMode interface{}
	switch mode {
	case "GCM":
		cipherMode, err = cipher.NewGCM(block)
	default:
		return nil, errors.New("unsupported cipher mode: " + mode)
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
		panic("unsupported cipher mode: " + fmt.Sprintf("%T", a.mode))
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
		panic("unsupported cipher mode: " + fmt.Sprintf("%T", a.mode))
	}
	return
}

func (a *AES) Sign(digest []byte, hash crypto.Hash) (signature []byte, err error) {
	return a.Encrypt(digest)
}

func (a *AES) Verify(digest []byte, signature []byte, hash crypto.Hash) (bool, error) {
	decryptedSignature, err := a.Decrypt(signature)
	if err != nil {
		return false, fmt.Errorf("decrypt signature failed: %w", err)
	}
	return bytes.Equal(decryptedSignature, digest), nil
}
