package crypto

import (
	"crypto"
	"fmt"
	"strings"
)

func Sign(hashAlgorithm string, encryptAlgorithm string, input []byte, key *Key, extraOpt any) (signature []byte, err error) {
	// hash
	digest, err := Hash(hashAlgorithm, input, nil)
	if err != nil {
		return
	}

	// 根据算法选择不同的签名方式
	var signer Signer
	switch strings.ToLower(encryptAlgorithm) {
	case CryptoAES:
		signer, err = NewAESWithKey(key, "GCM")
		if err != nil {
			return
		}
	case CryptoRSA:
		// 对于RSA，使用私钥进行签名
		// 尝试将key解析为RSA私钥
		var rsaPrivKey *RSAPrivateKey
		rsaPrivKey, err = DecodeToRSAPrivateKey(key.Key())
		if err != nil {
			return nil, err
		}
		// 创建RSA实例并进行签名
		signer = NewRSAWithPrivateKey(rsaPrivKey.PriKey())
		if extraOpt != nil {
			signer.(*RSA).SetPadding(extraOpt.(string))
		}
	default:
		err = fmt.Errorf("unsupported encrypt algorithm: %s", encryptAlgorithm)
	}
	if err != nil {
		return
	}

	var hash crypto.Hash
	hash, err = toHash(hashAlgorithm)
	if err != nil {
		return
	}
	signature, err = signer.Sign(digest, hash)
	return
}

func Verify(hashAlgorithm string, decryptAlgorithm string, input []byte, signature []byte, key *Key, extraOpt any) (success bool, err error) {
	// 计算输入数据的哈希值
	inputHash, err := Hash(hashAlgorithm, input, nil)
	if err != nil {
		return false, err
	}

	// 根据算法选择不同的验证方式
	var verifier Verifier
	switch strings.ToLower(decryptAlgorithm) {
	case CryptoAES:
		verifier, err = NewAESWithKey(key, "GCM")
	case CryptoRSA:
		// 对于RSA，使用公钥进行验证
		// 尝试将key解析为RSA公钥
		var rsaPubKey *RSAPublicKey
		rsaPubKey, err = DecodeToRSAPublicKey(key.Key())
		if err != nil {
			// 如果解析公钥失败，尝试解析私钥并使用其中的公钥部分
			var rsaPrivKey *RSAPrivateKey
			rsaPrivKey, err = DecodeToRSAPrivateKey(key.Key())
			if err != nil {
				return false, err
			}
			// 创建RSA实例并进行验证
			verifier = NewRSAWithPrivateKey(rsaPrivKey.PriKey())
		} else {
			// 创建RSA实例并进行验证
			verifier = NewRSAWithPublicKey(rsaPubKey.PubKey())
		}
		if extraOpt != nil {
			verifier.(*RSA).SetPadding(extraOpt.(string))
		}
	default:
		err = fmt.Errorf("unsupported decrypt algorithm: %s", decryptAlgorithm)
	}
	if err != nil {
		return
	}

	var hash crypto.Hash
	hash, err = toHash(hashAlgorithm)
	if err != nil {
		return
	}
	success, err = verifier.Verify(inputHash, signature, hash)
	return
}
