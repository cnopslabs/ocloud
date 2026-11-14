package auth

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/cnopslabs/ocloud/internal/services/configuration/session"
	"github.com/spf13/cobra"
)

var validateLong = `
Check whether an OCI session token is still valid. This is a native replacement for
'oci session validate' and prints the same messages to stderr.

By default the session is checked against OCI (a read-only ListRegions call), so a
revoked session is reported as invalid. Use --local to only check the token's expiry
time without any network call.

Exit status is 0 when the session is valid and 1 otherwise.
`

var validateExamples = `
  # Check the current profile ($OCI_CLI_PROFILE or DEFAULT) against OCI
  ocloud config session validate

  # Only check the expiry time, offline
  ocloud config session validate --local

  # Check a specific profile
  ocloud config session validate --profile DEV
`

var refreshLong = `
Refresh an OCI session token before it expires. This is a native replacement for
'oci session refresh': it exchanges the current token for a new one and rewrites the
profile's security_token_file. ~/.oci/config is not changed.

A session can only be refreshed while it is still valid, and only up to the maximum
session lifetime set by OCI (usually 24 hours). After that, run
'ocloud config session authenticate' to sign in again.
`

var refreshExamples = `
  # Refresh the current profile ($OCI_CLI_PROFILE or DEFAULT)
  ocloud config session refresh

  # Refresh a specific profile
  ocloud config session refresh --profile DEV
`

type sessionFlags struct {
	profile    string
	configFile string
}

func addSessionFlags(cmd *cobra.Command, f *sessionFlags) {
	cmd.Flags().StringVar(&f.profile, "profile", session.DefaultProfile(), "OCI config profile (defaults to $OCI_CLI_PROFILE or DEFAULT)")
	cmd.Flags().StringVar(&f.configFile, "config-file", session.DefaultConfigFile(), "OCI config file (defaults to $OCI_CLI_CONFIG_FILE or ~/.oci/config)")
}

// NewValidateCmd creates `ocloud config session validate`.
func NewValidateCmd() *cobra.Command {
	var f sessionFlags
	var local bool
	cmd := &cobra.Command{
		Use:           "validate",
		Short:         "Check whether an OCI session is still valid (replaces 'oci session validate')",
		Long:          validateLong,
		Example:       validateExamples,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var exp time.Time
			var err error
			if local {
				exp, err = session.ValidateLocal(f.configFile, f.profile, time.Now())
			} else {
				ctx, cancel := context.WithTimeout(cmdContext(cmd), 30*time.Second)
				defer cancel()
				exp, err = session.ValidateRemote(ctx, f.configFile, f.profile, "", nil)
			}
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), session.ValidMessage(exp))
			return nil
		},
	}
	addSessionFlags(cmd, &f)
	cmd.Flags().BoolVar(&local, "local", false, "Only check the token's expiry time, without calling OCI")
	return cmd
}

// NewRefreshCmd creates `ocloud config session refresh`.
func NewRefreshCmd() *cobra.Command {
	var f sessionFlags
	cmd := &cobra.Command{
		Use:           "refresh",
		Short:         "Refresh an OCI session token (replaces 'oci session refresh')",
		Long:          refreshLong,
		Example:       refreshExamples,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := (&session.Refresher{}).Refresh(cmdContext(cmd), f.configFile, f.profile)
			if err != nil {
				if errors.Is(err, session.ErrSessionNotRefreshable) {
					return err
				}
				return fmt.Errorf("failed to refresh session for profile %q: %w", f.profile, err)
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Successfully refreshed token from %s\n%s\n", res.URL, session.ValidMessage(res.Expires))
			return nil
		},
	}
	addSessionFlags(cmd, &f)
	return cmd
}

func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// NewRefresherCmd creates the hidden `ocloud config session refresher` command: the
// background loop started by `session authenticate`. It replaces oci_auth_refresher.sh.
func NewRefresherCmd() *cobra.Command {
	var f sessionFlags
	cmd := &cobra.Command{
		Use:           session.RefresherCommand,
		Short:         "Keep an OCI session alive in the background (started by 'session authenticate')",
		Hidden:        true,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmdContext(cmd), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			signal.Ignore(syscall.SIGHUP) // keep running when the terminal that started us closes
			d := &session.Daemon{ConfigFile: f.configFile, Profile: f.profile, Log: cmd.ErrOrStderr()}
			return d.Run(ctx)
		},
	}
	addSessionFlags(cmd, &f)
	return cmd
}
