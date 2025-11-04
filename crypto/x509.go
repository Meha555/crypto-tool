package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// TimeInterval
// (NotBefore, NotAfter)
type TimeInterval struct {
	notBefore time.Time
	notAfter  time.Time
}

func NewTimeInterval(start time.Time, duration time.Duration) TimeInterval {
	return TimeInterval{
		notBefore: start,
		notAfter:  start.Add(duration),
	}
}

// CreateCA creates a new Certificate Authority
func CreateCA(commonName, country, organization string, timeInterval TimeInterval) ([]byte, []byte, error) {
	// 生成RSA私钥
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// 设置CA证书模板
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{country},
			Organization: []string{organization},
			CommonName:   commonName,
		},
		NotBefore: timeInterval.notBefore,
		NotAfter:  timeInterval.notAfter,

		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{},

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 创建自签名CA证书
	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// 编码证书为PEM格式
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	// 编码私钥为PEM格式
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	return caPEM, keyPEM, nil
}

// IssueCertificate issues a new certificate signed by a CA
func IssueCertificate(caCertPEM, caKeyPEM []byte, commonName, country, organization string, timeInterval TimeInterval) ([]byte, []byte, error) {
	// 解析CA证书
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// 解析CA私钥
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA private key")
	}

	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	rsaCAKey, ok := caKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA private key is not RSA key")
	}

	// 生成服务器证书私钥
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server RSA key: %w", err)
	}

	// 创建服务器证书模板

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{country},
			Organization: []string{organization},
			CommonName:   commonName,
		},
		NotBefore: timeInterval.notBefore,
		NotAfter:  timeInterval.notAfter,

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}

	// 签发服务器证书
	certBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPrivKey.PublicKey, rsaCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to issue certificate: %w", err)
	}

	// 编码证书为PEM格式
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// 编码私钥为PEM格式
	serverPrivKeyBytes, err := x509.MarshalPKCS8PrivateKey(serverPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal server private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: serverPrivKeyBytes,
	})

	return certPEM, keyPEM, nil
}
