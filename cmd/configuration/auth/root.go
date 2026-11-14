package auth

import (
	"github.com/spf13/cobra"
)

// Short description for the session command
var sessionShort = "Authenticate with OCI and refresh session tokens"

// Long description for the session command
var sessionLong = `Provides commands for authenticating with Oracle Cloud Infrastructure (OCI).

This command group includes subcommands for authenticating with OCI, validating sessions and refreshing session tokens.
The validate and refresh subcommands are native replacements for 'oci session validate' and 'oci session refresh'.
It allows you to interactively select your desired profile and region for authentication.`

// Examples for the session command
var sessionExamples = `  ocloud config session authenticate
  ocloud config s authenticate --filter us
  ocloud config s auth --realm OC1
  ocloud config s a -f us -r OC2
  ocloud config session validate --local
  ocloud config session refresh --profile DEV`

// NewSessionCmd creates a new cobra.Command for the session command group.
func NewSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "session",
		Aliases:       []string{"s"},
		Short:         sessionShort,
		Long:          sessionLong,
		Example:       sessionExamples,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no subcommand is specified, run the authenticate command
			return NewAuthenticateCmd().RunE(cmd, args)
		},
	}

	cmd.AddCommand(NewAuthenticateCmd())
	cmd.AddCommand(NewValidateCmd())
	cmd.AddCommand(NewRefreshCmd())

	return cmd
}
