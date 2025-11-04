package utils

import (
	"fmt"
	"os"
	"strings"

	"github.com/meha555/crypto-tool/crypto"
)

func Write(dst string, data []byte, perm os.FileMode) error {
	if dst == "" {
		fmt.Println(string(data))
	} else {
		err := os.WriteFile(dst, data, perm)
		if err != nil {
			return err
		}
	}
	return nil
}

func WriteString(dst string, str string, perm os.FileMode) error {
	if dst == "" {
		fmt.Println(str)
	} else {
		err := os.WriteFile(dst, []byte(str), perm)
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadKey(algorithm, key string) (rawKey *crypto.Key, err error) {
	switch strings.ToLower(algorithm) {
	case crypto.CryptoAES:
		rawKey, err = crypto.StringToKey(key)
	case crypto.CryptoRSA:
		var privKeyData []byte
		privKeyData, err = os.ReadFile(key)
		if err != nil {
			return
		}
		rawKey = crypto.NewKey(privKeyData)
	default:
		err = fmt.Errorf("algorithm %s not supported", algorithm)
	}
	return
}
