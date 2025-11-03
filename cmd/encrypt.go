/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/meha555/crypto-tool/crypto"
	"github.com/spf13/cobra"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt -c <encryption-algorithm> -i <input-file> -o <output-file> -k <key>",
	Short: "Encrypt a file using a specified encryption algorithm",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var rawKey *crypto.Key
		if encryptKey == "" {
			rawKey, err = crypto.GenerateKey(int(encryKeyLength))
			if err != nil {
				return
			}
			fmt.Printf("Generate key: %s\n", rawKey.String())
		} else {
			rawKey, err = crypto.StringToKey(encryptKey)
			if err != nil {
				return
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
	encryKeyLength   uint32
)

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file")
	encryptCmd.Flags().StringVarP(&encryptAlgorithm, "crypto", "c", "", "encrypt algorithm")
	encryptCmd.Flags().StringVarP(&encryptKey, "key", "k", "", "encrypt key")
	encryptCmd.Flags().Uint32VarP(&encryKeyLength, "key-length", "l", 32, "key length")
	MarkFlagsRequired(encryptCmd, "crypto", "input")
	encryptCmd.MarkFlagsMutuallyExclusive("key", "key-length")
}
