package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strings"
)

func Hash(algorithm string, input []byte, salt []byte) (output []byte, err error) {
	// salt + text
	if len(salt) > 0 {
		input = append(salt, input...)
	}
	switch strings.ToLower(algorithm) {
	case "md5":
		md5sum := md5.Sum(input) // 16 bytes
		output = md5sum[:]
	case "sha1":
		sha1sum := sha1.Sum(input) // 20 bytes
		output = sha1sum[:]
	case "sha256":
		sha256sum := sha256.Sum256(input) // 32 bytes
		output = sha256sum[:]
	case "sha512":
		sha512sum := sha512.Sum512(input) // 64 bytes
		output = sha512sum[:]
	default:
		err = fmt.Errorf("hash algorithm %s not supported", algorithm)
	}
	return
}
