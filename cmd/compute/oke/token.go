package oke

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cnopslabs/ocloud/internal/services/compute/oke"
	"github.com/cnopslabs/ocloud/internal/services/configuration/session"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/spf13/cobra"
)

const (
	authSecurityToken = "security_token"
	authAPIKey        = "api_key"

	// LegacyTokenCommandName is the v0.2.0 top-level name, kept as a hidden alias so
	// hand-written kubeconfigs that call `ocloud oke-token` keep working.
	LegacyTokenCommandName = "oke-token"
)

var tokenLong = `
Generate a Kubernetes ExecCredential token for an OKE cluster.

This is a native replacement for 'oci ce cluster generate-token': kubectl runs it from
the exec section of a kubeconfig user to authenticate to the cluster, so the OCI CLI is
not needed. You do not normally run it yourself; 'ocloud identity bastion create' writes
kubeconfig entries that call it.

The token is valid for 4 minutes; kubectl caches it and calls the command again when it
expires. If your OCI session has expired, the command exits with an error telling you to
run 'ocloud config session authenticate' (it never prompts, since kubectl cannot answer).

Additional Information:
- The profile comes from --profile, else $OCI_CLI_PROFILE, else DEFAULT
- The region defaults to the profile's region
- Use --auth api_key for API-key profiles (default: security_token)
- Output is ExecCredential JSON on stdout; errors go to stderr
`

var tokenExamples = `
  # Print an ExecCredential for a cluster
  ocloud compute oke token --cluster-id ocid1.cluster.oc1.iad.xxx --region us-ashburn-1

  # Use a specific profile
  ocloud compute oke token --cluster-id ocid1.cluster.oc1.iad.xxx --profile DEV

  # kubeconfig user entry that calls it (what 'bastion create' writes)
  users:
  - name: user-xxx
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: ocloud
        args: [compute, oke, token, --cluster-id, ocid1.cluster.oc1.iad.xxx, --region, us-ashburn-1]
        interactiveMode: Never
`

// NewTokenCmd creates `ocloud compute oke token`, a kubectl exec credential plugin for OKE.
// It does not use the application context: kubectl calls it often, so it must start fast,
// skip tenancy/compartment lookups and print only the ExecCredential JSON on stdout.
func NewTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "token",
		Short:         "Generate a kubectl ExecCredential token for an OKE cluster (no OCI CLI needed)",
		Long:          tokenLong,
		Example:       tokenExamples,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	addTokenFlags(cmd)
	return cmd
}

// NewLegacyTokenCmd creates the hidden, deprecated top-level `ocloud oke-token` alias.
func NewLegacyTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           LegacyTokenCommandName,
		Short:         "Deprecated: use 'ocloud compute oke token'",
		Hidden:        true,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	addTokenFlags(cmd)
	run := cmd.RunE
	cmd.RunE = func(c *cobra.Command, args []string) error {
		// stderr only: stdout must stay pure ExecCredential JSON for kubectl.
		_, _ = fmt.Fprintln(c.ErrOrStderr(), "Warning: 'ocloud oke-token' is deprecated; use 'ocloud compute oke token'.")
		return run(c, args)
	}
	return cmd
}

func addTokenFlags(cmd *cobra.Command) {
	var clusterID, region, profile, auth, configFile string

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if auth == authSecurityToken {
			if err := ensureFreshSession(cmd, configFile, profile); err != nil {
				return err
			}
		}
		provider, err := newProvider(configFile, profile, auth)
		if err != nil {
			return err
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
	}

	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "OCID of the OKE cluster (required)")
	cmd.Flags().StringVar(&region, "region", "", "OCI region of the cluster (defaults to the profile's region)")
	cmd.Flags().StringVar(&profile, "profile", session.DefaultProfile(), "OCI config profile (defaults to $OCI_CLI_PROFILE or DEFAULT)")
	cmd.Flags().StringVar(&auth, "auth", authSecurityToken, "Authentication type: security_token or api_key")
	cmd.Flags().StringVar(&configFile, "config-file", session.DefaultConfigFile(), "OCI config file (defaults to $OCI_CLI_CONFIG_FILE or ~/.oci/config)")
	_ = cmd.MarkFlagRequired("cluster-id")
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

// sessionRefreshWindow is how close to expiry the token command refreshes the session.
// kubectl calls the command at least every TokenTTL (4 min), so an active kubectl user
// keeps the session alive even without the background refresher.
const sessionRefreshWindow = 5 * time.Minute

// newRefresher is replaced in tests.
var newRefresher = func() *session.Refresher { return &session.Refresher{} }

// ensureFreshSession runs before signing a token for a session profile:
//   - expired session: fail fast, without prompting (the OCI CLI asks an interactive
//     question kubectl cannot answer); an expired session cannot be refreshed anyway
//   - expiring within sessionRefreshWindow: refresh it first (shared lock with the
//     background refresher, so only one process refreshes)
//   - refresh failed but the token is still valid: warn on stderr and carry on
//   - token unreadable or not a JWT: pass through and let OKE accept or reject it
func ensureFreshSession(cmd *cobra.Command, configFile, profile string) error {
	now := time.Now()
	exp, err := session.ValidateLocal(configFile, profile, now)
	switch {
	case errors.Is(err, session.ErrSessionExpired):
		return fmt.Errorf("OCI session for profile %q expired at %s; run `ocloud config session authenticate`",
			profile, exp.Local().Format(time.RFC1123))
	case err != nil:
		return nil
	case exp.Sub(now) > sessionRefreshWindow:
		return nil
	}

	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	if _, _, err := newRefresher().RefreshIfExpiringWithin(ctx, configFile, profile, sessionRefreshWindow); err != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not refresh OCI session for profile %q (%v); using the current token, valid until %s\n",
			profile, err, exp.Local().Format(time.RFC1123))
	}
	return nil
}
