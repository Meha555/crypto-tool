package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

type RSAPublicKey struct {
	key *Key
	pub *rsa.PublicKey
}

func (r *RSAPublicKey) Key() *Key {
	return r.key
}

func (r *RSAPublicKey) PubKey() *rsa.PublicKey {
	return r.pub
}

func DecodeToRSAPublicKey(key []byte) (pubKey *RSAPublicKey, err error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA public key")
	}
	return &RSAPublicKey{
		key: &Key{
			key,
		},
		pub: rsaPub,
	}, nil
}

func EncodePublicKeyToMemory(pubKey *rsa.PublicKey) ([]byte, error) {
	derPubK, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPubK,
	}
	return pem.EncodeToMemory(pubBlock), nil
}

type RSAPrivateKey struct {
	key *Key
	pri *rsa.PrivateKey
}

func (r *RSAPrivateKey) Key() *Key {
	return r.key
}

func (r *RSAPrivateKey) PriKey() *rsa.PrivateKey {
	return r.pri
}

func DecodeToRSAPrivateKey(key []byte) (priKey *RSAPrivateKey, err error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key")
	}
	pri, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	rsaPriv, ok := pri.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA private key")
	}
	return &RSAPrivateKey{
		key: &Key{
			key,
		},
		pri: rsaPriv,
	}, nil
}

func EncodePrivateKeyToMemory(privKey *rsa.PrivateKey) ([]byte, error) {
	derPriK, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	priBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derPriK,
	}
	return pem.EncodeToMemory(priBlock), nil
}

type RSA struct {
	pubKey  *rsa.PublicKey
	privKey *rsa.PrivateKey
	padding string
}

func (r *RSA) PrivKey() *rsa.PrivateKey {
	return r.privKey
}

func (r *RSA) PubKey() *rsa.PublicKey {
	return r.pubKey
}

// SetPadding 设置RSA填充模式
func (r *RSA) SetPadding(padding string) {
	r.padding = padding
}

func GenerateRSAKeyPair(bits int /*, keyType string*/) (pubKey *Key, privKey *Key, err error) {
	var priK *rsa.PrivateKey
	priK, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	pubK := &priK.PublicKey

	var derPriK, derPubK []byte
	derPriK, err = x509.MarshalPKCS8PrivateKey(priK)
	if err != nil {
		return
	}
	priBlock := &pem.Block{
		// Type:  keyTypes[keyType]["PRIVATE"],
		Type:  "PRIVATE KEY",
		Bytes: derPriK,
	}
	privKey = &Key{
		key: pem.EncodeToMemory(priBlock),
	}

	derPubK, err = x509.MarshalPKIXPublicKey(pubK)
	if err != nil {
		return
	}
	pubBlock := &pem.Block{
		// Type:  keyTypes[keyType]["PUBLIC"],
		Type:  "PUBLIC KEY",
		Bytes: derPubK,
	}
	pubKey = &Key{
		key: pem.EncodeToMemory(pubBlock),
	}
	return
}

// func LoadPrivKey(filePath string) (privKey *RSAPrivateKey, err error) {
// 	var privKeyData []byte
// 	privKeyData, err = os.ReadFile(filePath)
// 	if err != nil {
// 		return
// 	}
// 	return DecodeToRSAPrivateKey(privKeyData)
// 	// // decode pem
// 	// block, _ := pem.Decode(privKeyData)
// 	// if block == nil {
// 	// 	return nil, fmt.Errorf("failed to decode private key")
// 	// }
// 	// // parse private key
// 	// // switch block.Type {
// 	// // case keyTypes["PKCS1"]["PRIVATE"]:
// 	// // 	privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
// 	// // case keyTypes["PKCS8"]["PRIVATE"]:
// 	// var pk any
// 	// pk, err = x509.ParsePKCS8PrivateKey(block.Bytes)
// 	// if err != nil {
// 	// 	return
// 	// }
// 	// var ok bool
// 	// privKey, ok = pk.(*rsa.PrivateKey)
// 	// if !ok {
// 	// 	return nil, errors.New("private key is not RSA private key")
// 	// }
// 	// // default:
// 	// // 	return nil, fmt.Errorf("unsupporteded key type: %s", block.Type)
// 	// // }
// 	// return
// }

// NewRSAWithPublicKey 创建一个使用公钥的RSA加密器
func NewRSAWithPublicKey(pubKey *rsa.PublicKey) *RSA {
	return &RSA{
		pubKey:  pubKey,
		padding: RSAPaddingPKCS1, // 默认使用PKCS1填充
	}
}

// NewRSAWithPrivateKey 创建一个使用私钥的RSA解密器
func NewRSAWithPrivateKey(privKey *rsa.PrivateKey) *RSA {
	return &RSA{
		privKey: privKey,
		pubKey:  &privKey.PublicKey,
		padding: RSAPaddingPKCS1, // 默认使用PKCS1填充
	}
}

// Encrypt 使用RSA公钥加密数据
func (r *RSA) Encrypt(plainText []byte) (cipherText []byte, err error) {
	if r.pubKey == nil {
		return nil, fmt.Errorf("RSA public key is required for encryption")
	}

	switch r.padding {
	case RSAPaddingNone:
		// 不使用填充（不推荐，仅用于兼容性）
		// 手动通过模幂运算实现
		k := (r.pubKey.N.BitLen() + 8 - 1) / 8 // 向上取整将位转换位字节数
		// 即使在"无填充"模式下，出于安全考虑，仍然需要保留一定的空间
		// 11字节包括：
		// - 1字节的类型标识符（通常是0x00或0x01或0x02）
		// - 至少8字节的随机填充（用于安全性）
		// - 1字节的分隔符（通常是0x00）
		// 总计至少10字节，加上安全余量就是11字节
		if len(plainText) > k-11 {
			return nil, fmt.Errorf("message too long for RSA encryption without padding")
		}
		m := new(big.Int).SetBytes(plainText)
		e := big.NewInt(int64(r.pubKey.E))
		c := new(big.Int).Exp(m, e, r.pubKey.N)
		cipherText = c.Bytes()

		// 确保输出长度正确
		if len(cipherText) < k {
			padded := make([]byte, k)
			copy(padded[k-len(cipherText):], cipherText)
			cipherText = padded
		}
	case RSAPaddingOAEP:
		// 使用OAEP填充
		cipherText, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, r.pubKey, plainText, nil)
		if err != nil {
			return nil, fmt.Errorf("RSA encryption with OAEP failed: %w", err)
		}
	case RSAPaddingPKCS1:
		fallthrough
	default:
		// 使用PKCS1 v1.5填充（默认）
		cipherText, err = rsa.EncryptPKCS1v15(rand.Reader, r.pubKey, plainText)
		if err != nil {
			return nil, fmt.Errorf("RSA encryption with PKCS1 failed: %w", err)
		}
	}

	return
}

// Decrypt 使用RSA私钥解密数据
func (r *RSA) Decrypt(cipherText []byte) (plainText []byte, err error) {
	if r.privKey == nil {
		return nil, fmt.Errorf("RSA private key is required for decryption")
	}

	switch r.padding {
	case RSAPaddingNone:
		// 不使用填充解密（不推荐，仅用于兼容性）
		// 手动通过模幂运算实现
		k := (r.privKey.N.BitLen() + 8 - 1) / 8 // 向上取整将位转换位字节数
		if len(cipherText) != k {
			return nil, fmt.Errorf("ciphertext length does not match RSA key size")
		}

		c := new(big.Int).SetBytes(cipherText)
		m := new(big.Int).Exp(c, r.privKey.D, r.privKey.N)
		plainText = m.Bytes()

		// 确保输出长度正确
		if len(plainText) < k {
			padded := make([]byte, k)
			copy(padded[k-len(plainText):], plainText)
			plainText = padded
		}
	case RSAPaddingOAEP:
		// 使用OAEP填充解密
		plainText, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, r.privKey, cipherText, nil)
		if err != nil {
			return nil, fmt.Errorf("RSA decryption with OAEP failed: %w", err)
		}
	case RSAPaddingPKCS1:
		fallthrough
	default:
		// 使用PKCS1 v1.5填充解密（默认）
		plainText, err = rsa.DecryptPKCS1v15(rand.Reader, r.privKey, cipherText)
		if err != nil {
			return nil, fmt.Errorf("RSA decryption with PKCS1 failed: %w", err)
		}
	}

	return
}

// Sign 使用RSA私钥对数据进行签名
func (r *RSA) Sign(digest []byte, hash crypto.Hash) (signature []byte, err error) {
	if r.privKey == nil {
		return nil, fmt.Errorf("RSA private key is required for signing")
	}
	// 使用RSA私钥对哈希值进行签名
	signature, err = rsa.SignPKCS1v15(rand.Reader, r.privKey, hash, digest)
	if err != nil {
		return nil, fmt.Errorf("RSA signing failed: %w", err)
	}
	return
}

// Verify 使用RSA公钥验证签名
func (r *RSA) Verify(digest []byte, signature []byte, hash crypto.Hash) (bool, error) {
	if r.pubKey == nil {
		return false, fmt.Errorf("RSA public key is required for verification")
	}
	// 使用RSA公钥验证签名
	err := rsa.VerifyPKCS1v15(r.pubKey, hash, digest, signature)
	if err != nil {
		return false, fmt.Errorf("RSA verification failed: %w", err)
	}
	return true, nil
}

// 验证填充模式是否有效
func ValidatePaddingMode(mode string) bool {
	switch mode {
	case "pkcs1", "oaep", "none":
		return true
	default:
		return false
	}
}
