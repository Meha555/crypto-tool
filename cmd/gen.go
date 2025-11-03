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

// genCmd represents the gen command
var genCmd = &cobra.Command{
	Use:   "gen -c <encryption-algorithm> -l <key-length> -o <output-file>",
	Short: "Generate keys for specified algorithm",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var key *crypto.Key
		var length int

		// Set key length based on algorithm
		switch genAlgorithm {
		case "AES":
			length = int(genLength)
			key, err = crypto.GenerateKey(length)
			if err != nil {
				return fmt.Errorf("failed to generate key: %w", err)
			}
		// case "RSA":
		// 	length = int(genLength)
		// 	key, err = crypto.GenerateKey(length)
		// 	if err != nil {
		// 		return fmt.Errorf("failed to generate key: %w", err)
		// 	}
		default:
			return fmt.Errorf("unsupported algorithm: %s", genAlgorithm)
		}

		// Output key
		if outputFile == "" {
			fmt.Println(key.String())
		} else {
			err = os.WriteFile(outputFile, []byte(key.String()), 0644)
			if err != nil {
				return fmt.Errorf("failed to write key to file: %w", err)
			}
			fmt.Printf("Key generated and saved to %s\n", outputFile)
		}

		return nil
	},
}

var (
	genAlgorithm string
	genLength    uint32
)

func init() {
	rootCmd.AddCommand(genCmd)

	genCmd.Flags().StringVarP(&genAlgorithm, "crypto", "c", "", "encryption algorithm")
	genCmd.Flags().Uint32VarP(&genLength, "key-length", "l", 32, "key length (bytes)")
	MarkFlagsRequired(genCmd, "crypto")
}
