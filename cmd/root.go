/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "crypto-tool",
	Short: "A cli tool for crypto operations",
	RunE: func(cmd *cobra.Command, args []string) error {
		if versionFlag {
			fmt.Println(version)
		}
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
	inputFile   string
	outputFile  string
	versionFlag bool
	version     string
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output file")
	rootCmd.Flags().BoolVarP(&versionFlag, "version", "v", false, "print version")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func MarkFlagsRequired(cmd *cobra.Command, flagName ...string) {
	for _, flagName := range flagName {
		if err := cmd.MarkFlagRequired(flagName); err != nil {
			panic(err)
		}
	}
}
