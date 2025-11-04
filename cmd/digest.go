/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"encoding/hex"
	"os"

	"github.com/meha555/crypto-tool/crypto"
	"github.com/meha555/crypto-tool/utils"
	"github.com/spf13/cobra"
)

// digestCmd represents the hash command
var digestCmd = &cobra.Command{
	Use:   "digest -d <hash-algorithm> -i <input-file> -s <salt>",
	Short: "Digest a file using a specified hash algorithm",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var inputData, outputData []byte
		inputData, err = os.ReadFile(inputFile)
		if err != nil {
			return
		}
		salt := []byte(digestSalt) // 不当作hexstring
		outputData, err = crypto.Hash(digestAlgorithm, inputData, salt)
		if err != nil {
			return
		}
		err = utils.WriteString(outputFile, hex.EncodeToString(outputData), 0o644)
		return
	},
}

var (
	digestAlgorithm string
	digestSalt      string
)

func init() {
	rootCmd.AddCommand(digestCmd)

	digestCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file")
	digestCmd.Flags().StringVarP(&digestAlgorithm, "digest", "d", "", "hash algorithm")
	// 盐值不要用字符串读取，因为人输入的时候就是对应二进制转成十六进制字符串
	digestCmd.Flags().StringVarP(&digestSalt, "salt", "s", "", "hash salt (hex string)")
	MarkFlagsRequired(digestCmd, "digest", "input")
}
