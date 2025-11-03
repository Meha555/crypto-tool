/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign data with specified algorithm",
	Long: `Sign data with specified algorithm.

For example:

sign -c <encryption-algorithm> -d <hash-algorithm> -i <input-file> -o <output-file> -k <key>`,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		
		return
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
	MarkFlagsRequired(signCmd, "crypto", "hash", "input")
}
