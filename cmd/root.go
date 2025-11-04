/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:              "crypto-tool",
	Short:            "A cli tool for crypto operations",
	Version:          version,
	Args:             cobra.NoArgs,
	TraverseChildren: true,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var (
	version     string
	inputFile   string
	outputFile  string
	paddingMode string
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output file")
	rootCmd.PersistentFlags().StringVarP(&paddingMode, "padding", "p", "pkcs1", "padding mode (pkcs1, oaep, none)")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func MarkFlagsRequired(cmd *cobra.Command, flagName ...string) {
	for _, flagName := range flagName {
		if err := cmd.MarkFlagRequired(flagName); err != nil {
			panic(err)
		}
	}
}
