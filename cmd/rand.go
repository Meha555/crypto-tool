/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

// randCmd represents the rand command
var randCmd = &cobra.Command{
	Use:   "rand",
	Short: "rand <bits> [--base64]",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		bits, err := strconv.Atoi(args[0])
		if err != nil {
			return err
		}
		buf := make([]byte, bits)
		_, err = rand.Read(buf)
		if err != nil {
			return err
		}
		if base64Encode {
			fmt.Println(base64.StdEncoding.EncodeToString(buf))
		} else {
			fmt.Println(string(buf))
		}
		return nil
	},
}

var base64Encode bool

func init() {
	rootCmd.AddCommand(randCmd)

	randCmd.Flags().BoolVar(&base64Encode, "base64", false, "encode with base64")
}
