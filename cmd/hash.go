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

// hashCmd represents the hash command
var hashCmd = &cobra.Command{
	Use:   "hash -d <hash-algorithm> -i <input-file> -s <salt>",
	Short: "Hash a file using a specified hash algorithm",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var inputData, outputData []byte
		inputData, err = os.ReadFile(inputFile)
		if err != nil {
			return
		}
		salt := []byte(hashSalt) // 不当作hexstring
		outputData, err = crypto.Hash(hashAlgorithm, inputData, salt)
		if err != nil {
			return
		}
		err = utils.WriteString(outputFile, hex.EncodeToString(outputData), 0644)
		return
	},
}

var (
	hashAlgorithm string
	hashSalt      string
)

func init() {
	rootCmd.AddCommand(hashCmd)

	hashCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file")
	hashCmd.Flags().StringVarP(&hashAlgorithm, "digest", "d", "", "hash algorithm")
	// 盐值不要用字符串读取，因为人输入的时候就是对应二进制转成十六进制字符串
	hashCmd.Flags().StringVarP(&hashSalt, "salt", "s", "", "hash salt (hex string)")
	MarkFlagsRequired(hashCmd, "digest", "input")
}
