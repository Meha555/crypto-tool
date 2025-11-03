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

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file using a specified encryption algorithm",
	Long: `Decrypt a file using a specified encryption algorithm.

For example:

decrypt -c <encryption-algorithm> -i <input-file> -o <output-file> -k <key>`,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		rawKey, err := base64.StdEncoding.DecodeString(decryptKey)
		if err != nil {
			return fmt.Errorf("decode key failed: %w", err)
		}
		var decrypter crypto.Decrypter
		switch decryptAlgorithm {
		case "AES":
			decrypter, err = crypto.NewAESWithKey(rawKey, "GCM")
		default:
			err = fmt.Errorf("unsupport decrypt algorithm: %s", decryptAlgorithm)
		}
		if err != nil {
			return
		}

		var cipherData, plainData []byte
		cipherData, err = os.ReadFile(inputFile)
		if err != nil {
			return
		}
		plainData, err = decrypter.Decrypt(cipherData)
		if err != nil {
			return
		}
		if outputFile == "" {
			_, err = fmt.Printf("%s", plainData)
		} else {
			err = os.WriteFile(outputFile, plainData, 0644)
		}
		return
	},
}

var (
	decryptAlgorithm string
	decryptKey       string
)

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file")
	decryptCmd.Flags().StringVarP(&decryptAlgorithm, "crypto", "c", "", "decrypt algorithm")
	decryptCmd.Flags().StringVarP(&decryptKey, "key", "k", "", "decrypt key")
	MarkFlagsRequired(decryptCmd, "crypto", "input", "key")
}
