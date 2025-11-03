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

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify -c <encryption-algorithm> -d <hash-algorithm> -s <signature-file/string> -i <input-file>",
	Short: "Verify a signature with specified algorithm",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		// Read input file
		var inputData []byte
		inputData, err = os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}

		// Decode key
		var rawKey *crypto.Key
		rawKey, err = crypto.StringToKey(verifyKey)
		if err != nil {
			return
		}

		// Read signature
		var signature []byte
		if _, err = os.Stat(verifySignature); err == nil {
			// Signature is a file
			signature, err = os.ReadFile(verifySignature)
			if err != nil {
				return fmt.Errorf("failed to read signature file: %w", err)
			}
		} else {
			// Signature is a base64 string
			signature, err = base64.StdEncoding.DecodeString(verifySignature)
			if err != nil {
				return fmt.Errorf("failed to decode signature: %w", err)
			}
		}

		// Verify signature
		var success bool
		success, err = crypto.Verify(verifyHashAlgorithm, verifyEncryptAlgorithm, inputData, signature, rawKey)
		if err != nil {
			return fmt.Errorf("failed to verify signature: %w", err)
		}

		if success {
			fmt.Println("Signature verified successfully")
		} else {
			fmt.Println("Signature verification failed")
		}

		return nil
	},
}

var (
	verifyKey              string
	verifyEncryptAlgorithm string
	verifyHashAlgorithm    string
	verifySignature        string
)

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file")
	verifyCmd.Flags().StringVarP(&verifyKey, "key", "k", "", "key")
	verifyCmd.Flags().StringVarP(&verifyEncryptAlgorithm, "crypto", "c", "", "encryption algorithm")
	verifyCmd.Flags().StringVarP(&verifyHashAlgorithm, "hash", "d", "", "hash algorithm")
	verifyCmd.Flags().StringVarP(&verifySignature, "signature", "s", "", "signature file or base64 encoded string")
	MarkFlagsRequired(verifyCmd, "crypto", "hash", "input", "key", "signature")
}
