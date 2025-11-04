/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"os"

	"github.com/meha555/crypto-tool/crypto"
	"github.com/meha555/crypto-tool/utils"
	"github.com/spf13/cobra"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt -c <encryption-algorithm> -i <input-file> -o <output-file> -k <key>",
	Short: "Encrypt a file using a specified encryption algorithm",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var rawKey *crypto.Key
		rawKey, err = utils.ReadKey(encryptAlgorithm, encryptKey)
		if err != nil {
			return
		}

		var plainData, cipherData []byte
		plainData, err = os.ReadFile(inputFile)
		if err != nil {
			return
		}
		cipherData, err = crypto.Encrypt(encryptAlgorithm, plainData, rawKey)
		if err != nil {
			return
		}
		return utils.Write(outputFile, cipherData, 0o644)
	},
}

var (
	encryptAlgorithm string
	encryptKey       string
)

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file")
	encryptCmd.Flags().StringVarP(&encryptAlgorithm, "crypto", "c", "", "encrypt algorithm")
	encryptCmd.Flags().StringVarP(&encryptKey, "key", "k", "", "encrypt [public] key")
	MarkFlagsRequired(encryptCmd, "crypto", "input", "key")
	encryptCmd.MarkFlagsMutuallyExclusive("key")
}
