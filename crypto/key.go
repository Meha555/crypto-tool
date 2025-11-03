package crypto

import (
	"encoding/base64"
	"fmt"
)

type Key struct {
	key []byte
}

func (k *Key) Key() []byte {
	return k.key
}

func (k *Key) String() string {
	return base64.StdEncoding.EncodeToString(k.key)
}

func (k *Key) Len() int {
	return len(k.key)
}

func StringToKey(base64Str string) (*Key, error) {
	key, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	return &Key{key: key}, nil
}
