/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/meha555/crypto-tool/crypto"
	"github.com/spf13/cobra"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file using a specified encryption algorithm",
	Long:  `encrypt -c <encryption-algorithm> -i <input-file> -o <output-file> -k <key>`,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var rawKey []byte
		if encryptKey == "" {
			rawKey, err = crypto.GenerateKey(int(keyLength))
			if err != nil {
				return
			}
			encryptKey = base64.StdEncoding.EncodeToString(rawKey)
			fmt.Printf("Generate key: %s\n", encryptKey)
		} else {
			rawKey, err = base64.StdEncoding.DecodeString(encryptKey)
			if err != nil {
				return fmt.Errorf("decode key failed: %w", err)
			}
		}

		var encrypter crypto.Encrypter
		switch encryptAlgorithm {
		case "AES":
			encrypter, err = crypto.NewAESWithKey(rawKey, "GCM")
		default:
			err = fmt.Errorf("unsupport encrypt algorithm: %s", encryptAlgorithm)
		}
		if err != nil {
			return
		}

		var plainData, cipherData []byte
		plainData, err = os.ReadFile(inputFile)
		if err != nil {
			return
		}
		cipherData, err = encrypter.Encrypt(plainData)
		if err != nil {
			return
		}
		return os.WriteFile(outputFile, cipherData, 0644)
	},
}

var (
	encryptAlgorithm string
	encryptKey       string
	keyLength        uint32
)

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file")
	encryptCmd.Flags().StringVarP(&encryptAlgorithm, "crypto", "c", "", "encrypt algorithm")
	encryptCmd.Flags().StringVarP(&encryptKey, "key", "k", "", "encrypt key")
	encryptCmd.Flags().Uint32VarP(&keyLength, "length", "l", 32, "key length")
	MarkFlagsRequired(encryptCmd, "crypto", "input")
	encryptCmd.MarkFlagsMutuallyExclusive("key", "length")
}
