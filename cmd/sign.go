/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/meha555/crypto-tool/crypto"
	"github.com/meha555/crypto-tool/utils"
	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign -c <encryption-algorithm> -d <hash-algorithm> -i <input-file> -o <output-file> -k <key>",
	Short: "Sign data with specified algorithm",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// 验证填充模式
		if !crypto.ValidatePaddingMode(paddingMode) {
			return fmt.Errorf("invalid padding mode: %s, must be one of pkcs1, oaep, none", paddingMode)
		}

		// Read input file
		var inputData []byte
		inputData, err = os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		var rawKey *crypto.Key
		rawKey, err = utils.ReadKey(signEncryptAlgorithm, signKey)
		if err != nil {
			return
		}

		// Sign data
		var signature []byte
		signature, err = crypto.Sign(signHashAlgorithm, signEncryptAlgorithm, inputData, rawKey, paddingMode)
		if err != nil {
			return fmt.Errorf("failed to sign data: %w", err)
		}

		// Output signature
		if outputFile == "" {
			fmt.Println(base64.StdEncoding.EncodeToString(signature))
		} else {
			err = os.WriteFile(outputFile, signature, 0o644)
			if err != nil {
				return fmt.Errorf("failed to write signature to file: %w", err)
			}
		}

		return nil
	},
}

var (
	signKey              string
	signEncryptAlgorithm string
	signHashAlgorithm    string
)

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file")
	signCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file")
	signCmd.Flags().StringVarP(&signKey, "key", "k", "", "key")
	signCmd.Flags().StringVarP(&signEncryptAlgorithm, "crypto", "c", "", "encryption algorithm")
	signCmd.Flags().StringVarP(&signHashAlgorithm, "hash", "d", "", "hash algorithm")
	MarkFlagsRequired(signCmd, "crypto", "hash", "input", "key")
}
