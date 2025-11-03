/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "crypto-tool",
	Short: "A cli tool for crypto operations",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	TraverseChildren: true,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var (
	inputFile  string
	outputFile string
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output file")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func MarkFlagsRequired(cmd *cobra.Command, flagName ...string) {
	for _, flagName := range flagName {
		if err := cmd.MarkFlagRequired(flagName); err != nil {
			panic(err)
		}
	}
}
