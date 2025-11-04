/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/meha555/crypto-tool/crypto"
	"github.com/meha555/crypto-tool/utils"
	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt -c <encryption-algorithm> -i <input-file> -o <output-file> -k <key>",
	Short: "Decrypt a file using a specified encryption algorithm",
	Args:  cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) (err error) {
		// 验证填充模式
		if !crypto.ValidatePaddingMode(paddingMode) {
			return fmt.Errorf("invalid padding mode: %s, must be one of pkcs1, oaep, none", paddingMode)
		}

		var rawKey *crypto.Key
		rawKey, err = utils.ReadKey(decryptAlgorithm, decryptKey)
		if err != nil {
			return
		}

		var cipherData, plainData []byte
		cipherData, err = os.ReadFile(inputFile)
		if err != nil {
			return
		}
		plainData, err = crypto.Decrypt(decryptAlgorithm, cipherData, rawKey, paddingMode)
		if err != nil {
			return
		}

		utils.Write(outputFile, plainData, 0o644)
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
	decryptCmd.Flags().StringVarP(&decryptKey, "key", "k", "", "decrypt [private] key")
	MarkFlagsRequired(decryptCmd, "crypto", "input", "key")
}
