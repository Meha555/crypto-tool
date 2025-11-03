/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/meha555/crypto-tool/crypto"
	"github.com/meha555/crypto-tool/utils"
	"github.com/spf13/cobra"
)

// genCmd represents the gen command
var genCmd = &cobra.Command{
	Use:   "gen -c <encryption-algorithm> -l <key-length> -o <output-file>",
	Short: "Generate keys for specified algorithm",
	PreRunE: func(cmd *cobra.Command, args []string) (err error) {
		if genKeyLength == 0 && genPrivKey == "" {
			return fmt.Errorf("either key-length or priv-key must be specified")
		}
		return
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var key *crypto.Key
		switch strings.ToLower(genAlgorithm) {
		case crypto.CryptoAES:
			key, err = crypto.GenerateKey(int(genKeyLength))
			if err != nil {
				return fmt.Errorf("failed to generate AES key: %w", err)
			}
			err = utils.Write(outputFile, []byte(key.String()), 0644)
		case crypto.CryptoRSA:
			if genPrivKey == "" {
				// 未指定私钥，说明要生成公私钥对
				pubKey, privKey, er := crypto.GenerateRSAKeyPair(int(genKeyLength))
				if er != nil {
					err = er
					return
				}

				utils.Write(outputFile, pubKey.Key(), 0644)
				utils.Write(outputFile, privKey.Key(), 0600)
			} else {
				// 否则说明是从私钥中提取公钥
				var (
					privKeyData []byte
					privKey     *crypto.RSAPrivateKey
					pubKey      []byte
				)
				privKeyData, err = os.ReadFile(genPrivKey)
				if err != nil {
					return
				}
				privKey, err = crypto.DecodeToRSAPrivateKey(privKeyData)
				if err != nil {
					return
				}

				pubKey, err = crypto.EncodePublicKeyToMemory(&privKey.PriKey().PublicKey)
				if err != nil {
					return
				}

				utils.Write(outputFile, pubKey, 0644)
			}

		default:
			return fmt.Errorf("unsupporteded algorithm: %s", genAlgorithm)
		}
		return
	},
}

var (
	genAlgorithm string
	genKeyLength uint32

	// 对于非对称加密特定
	genPrivKey string
)

func init() {
	rootCmd.AddCommand(genCmd)

	genCmd.Flags().StringVarP(&genAlgorithm, "crypto", "c", "", "encryption algorithm")
	genCmd.Flags().Uint32VarP(&genKeyLength, "key-length", "l", 0, "key length (bytes)")
	genCmd.Flags().StringVarP(&genPrivKey, "priv-key", "p", "", "private key")
	MarkFlagsRequired(genCmd, "crypto")
	genCmd.MarkFlagsMutuallyExclusive("key-length", "priv-key")
}
