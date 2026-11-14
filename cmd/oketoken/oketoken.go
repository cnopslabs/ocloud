// Package oketoken provides `ocloud oke-token`, a kubectl exec credential plugin for OKE
// that replaces `oci ce cluster generate-token` without requiring the OCI CLI.
package oketoken

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cnopslabs/ocloud/internal/config/flags"
	"github.com/cnopslabs/ocloud/internal/services/compute/oke"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/spf13/cobra"
)

const (
	// CommandName is the top-level command name. It must be registered as a no-context
	// command so kubectl invocations never trigger tenancy/compartment lookups.
	CommandName = "oke-token"

	authSecurityToken = "security_token"
	authAPIKey        = "api_key"

	envConfigFile = "OCI_CLI_CONFIG_FILE"
)

// NewCommand creates the `oke-token` command.
func NewCommand() *cobra.Command {
	var clusterID, region, profile, auth, configFile string

	cmd := &cobra.Command{
		Use:   CommandName,
		Short: "Generate a Kubernetes ExecCredential token for an OKE cluster (kubectl exec plugin)",
		Long: "Generate a Kubernetes ExecCredential token for an OKE cluster.\n" +
			"This is a native replacement for `oci ce cluster generate-token` and is meant to be\n" +
			"called by kubectl from a kubeconfig user entry; it does not need the OCI CLI.",
		Example:       "  ocloud oke-token --cluster-id ocid1.cluster.oc1.iad.xxx --region us-ashburn-1",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			provider, err := newProvider(configFile, profile, auth)
			if err != nil {
				return err
			}
			if auth == authSecurityToken {
				if err := checkSessionNotExpired(provider, profile, time.Now()); err != nil {
					return err
				}
			}
			if region == "" {
				if region, err = provider.Region(); err != nil {
					return fmt.Errorf("no --region given and none in profile %q: %w", profile, err)
				}
			}
			out, err := oke.GenerateExecCredentialJSON(common.DefaultRequestSigner(provider), region, clusterID, time.Now())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return err
		},
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "OCID of the OKE cluster (required)")
	cmd.Flags().StringVar(&region, "region", "", "OCI region of the cluster (defaults to the profile's region)")
	cmd.Flags().StringVar(&profile, "profile", defaultProfile(), "OCI config profile (defaults to $"+flags.EnvKeyProfile+" or DEFAULT)")
	cmd.Flags().StringVar(&auth, "auth", authSecurityToken, "Authentication type: security_token or api_key")
	cmd.Flags().StringVar(&configFile, "config-file", defaultConfigFile(), "OCI config file (defaults to $"+envConfigFile+" or ~/.oci/config)")
	_ = cmd.MarkFlagRequired("cluster-id")

	return cmd
}

func newProvider(configFile, profile, auth string) (common.ConfigurationProvider, error) {
	switch auth {
	case authSecurityToken:
		p, err := common.ConfigurationProviderForSessionTokenWithProfile(configFile, profile, "")
		if err != nil {
			return nil, fmt.Errorf("loading session token profile %q from %s: %w", profile, configFile, err)
		}
		return p, nil
	case authAPIKey:
		p, err := common.ConfigurationProviderFromFileWithProfile(configFile, profile, "")
		if err != nil {
			return nil, fmt.Errorf("loading api key profile %q from %s: %w", profile, configFile, err)
		}
		return p, nil
	default:
		return nil, fmt.Errorf("unsupported --auth %q (use %s or %s)", auth, authSecurityToken, authAPIKey)
	}
}

// checkSessionNotExpired fails fast, without prompting, when the session token has expired.
// The OCI CLI refuses here too, but asks an interactive question kubectl cannot answer.
// Tokens that cannot be parsed are passed through and left for OKE to accept or reject.
func checkSessionNotExpired(provider common.ConfigurationProvider, profile string, now time.Time) error {
	keyID, err := provider.KeyID()
	if err != nil {
		return fmt.Errorf("reading session token for profile %q: %w", profile, err)
	}
	exp, err := oke.SessionTokenExpiry(keyID)
	if err != nil {
		return nil
	}
	if !now.Before(exp) {
		return fmt.Errorf("OCI session for profile %q expired at %s; run `ocloud config session authenticate`",
			profile, exp.Local().Format(time.RFC1123))
	}
	return nil
}

func defaultProfile() string {
	if p := os.Getenv(flags.EnvKeyProfile); p != "" {
		return p
	}
	return flags.DefaultProfileName
}

func defaultConfigFile() string {
	if f := os.Getenv(envConfigFile); f != "" {
		return f
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join("~", flags.OCIConfigDirName, flags.OCIConfigFileName)
	}
	return filepath.Join(home, flags.OCIConfigDirName, flags.OCIConfigFileName)
}
