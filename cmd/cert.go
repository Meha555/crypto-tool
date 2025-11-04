/*
Copyright © 2025 Meha555
*/
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/meha555/crypto-tool/crypto"
	"github.com/spf13/cobra"
)

// certCmd represents the cert command
var certCmd = &cobra.Command{
	Use:              "cert",
	Short:            "Certificate management commands",
	Long:             `Manage certificates including creating CA, issuing certificates, etc.`,
	TraverseChildren: true,
}

// caCreateCmd represents the command to create a new CA
var caCreateCmd = &cobra.Command{
	Use:   "create-ca",
	Short: "Create a new Certificate Authority",
	Long:  `Create a new Certificate Authority with a self-signed certificate`,
	RunE: func(cmd *cobra.Command, args []string) error {
		caCertPEM, caKeyPEM, err := crypto.CreateCA(caCommonName, caCountry, caOrganization, crypto.NewTimeInterval(time.Now(), time.Hour*24*time.Duration(validDays)))
		if err != nil {
			return fmt.Errorf("failed to create CA: %w", err)
		}

		// 保存CA证书和私钥
		if err := os.WriteFile("ca.crt", caCertPEM, 0644); err != nil {
			return fmt.Errorf("failed to write CA certificate: %w", err)
		}

		if err := os.WriteFile(caOutputKey, caKeyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write CA private key: %w", err)
		}

		fmt.Printf("CA certificate saved to: ca.crt\n")
		fmt.Printf("CA private key saved to: %s\n", caOutputKey)
		fmt.Println("CA created successfully!")

		return nil
	},
}

// certIssueCmd represents the command to issue a new certificate
var certIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a new certificate",
	Long:  `Issue a new certificate signed by a CA`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 读取CA证书
		caCertPEM, err := os.ReadFile(issueCACert)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate: %w", err)
		}

		// 读取CA私钥
		caKeyPEM, err := os.ReadFile(issueCAKey)
		if err != nil {
			return fmt.Errorf("failed to read CA private key: %w", err)
		}

		// 签发证书
		certPEM, keyPEM, err := crypto.IssueCertificate(caCertPEM, caKeyPEM, issueCommonName, issueCountry, issueOrganization, crypto.NewTimeInterval(time.Now(), time.Hour*24*time.Duration(validDays)))
		if err != nil {
			return fmt.Errorf("failed to issue certificate: %w", err)
		}

		// 保存证书
		if err := os.WriteFile(issueOutputCert, certPEM, 0644); err != nil {
			return fmt.Errorf("failed to write certificate: %w", err)
		}

		// 保存私钥
		if err := os.WriteFile(issueOutputKey, keyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write private key: %w", err)
		}

		fmt.Printf("Certificate saved to: %s\n", issueOutputCert)
		fmt.Printf("Private key saved to: %s\n", issueOutputKey)
		fmt.Println("Certificate issued successfully!")

		return nil
	},
}

var (
	validDays uint64

	// CA相关标志
	caCommonName   string
	caCountry      string
	caOrganization string
	caOutputCert   string
	caOutputKey    string

	// 证书签发相关标志
	issueCommonName   string
	issueCountry      string
	issueOrganization string
	issueIPAddresses  []string
	issueDNSNames     []string
	issueOutputCert   string
	issueOutputKey    string
	issueCACert       string
	issueCAKey        string
)

func init() {
	rootCmd.AddCommand(certCmd)

	certCmd.PersistentFlags().Uint64Var(&validDays, "valid-days", 3650, "Validity period in days")

	// 添加创建CA子命令
	certCmd.AddCommand(caCreateCmd)
	caCreateCmd.Flags().StringVar(&caCommonName, "common-name", "CryptoTool CA", "Common name for the CA")
	caCreateCmd.Flags().StringVar(&caCountry, "country", "CN", "Country for the CA")
	caCreateCmd.Flags().StringVar(&caOrganization, "organization", "CryptoTool", "Organization for the CA")
	caCreateCmd.Flags().StringVarP(&caOutputCert, "cert-output", "c", "ca.crt", "Output file for CA certificate")
	caCreateCmd.Flags().StringVarP(&caOutputKey, "key-output", "k", "ca.key", "Output file for CA private key")

	// 添加签发证书子命令
	certCmd.AddCommand(certIssueCmd)
	certIssueCmd.Flags().StringVar(&issueCommonName, "common-name", "", "Common name for the certificate")
	certIssueCmd.Flags().StringVar(&issueCountry, "country", "CN", "Country for the certificate")
	certIssueCmd.Flags().StringVar(&issueOrganization, "organization", "CryptoTool", "Organization for the certificate")
	certIssueCmd.Flags().StringSliceVar(&issueIPAddresses, "ip", []string{}, "IP addresses for the certificate")
	certIssueCmd.Flags().StringSliceVar(&issueDNSNames, "dns", []string{}, "DNS names for the certificate")
	certIssueCmd.Flags().StringVarP(&issueOutputCert, "cert-output", "c", "server.crt", "Output file for certificate")
	certIssueCmd.Flags().StringVarP(&issueOutputKey, "key-output", "k", "server.key", "Output file for private key")
	certIssueCmd.Flags().StringVar(&issueCACert, "ca-cert", "ca.crt", "CA certificate file")
	certIssueCmd.Flags().StringVar(&issueCAKey, "ca-key", "ca.key", "CA private key file")
	certIssueCmd.MarkFlagRequired("common-name")
}
