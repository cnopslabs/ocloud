package cmd

import (
	"context"
	"fmt"
	"github.com/cnopslabs/ocloud/cmd/compute"
	"github.com/cnopslabs/ocloud/cmd/database"
	"github.com/cnopslabs/ocloud/cmd/identity"
	"github.com/cnopslabs/ocloud/cmd/network"
	"github.com/cnopslabs/ocloud/cmd/version"
	"github.com/cnopslabs/ocloud/internal/app"
	"github.com/cnopslabs/ocloud/internal/config/flags"
	"github.com/spf13/cobra"
)

// NewRootCmd creates a new root command with all subcommands attached
func NewRootCmd(appCtx *app.ApplicationContext) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "ocloud",
		Short:        "Interact with Oracle Cloud Infrastructure",
		Long:         "",
		SilenceUsage: true,
	}

	// Initialize global flags
	flags.AddGlobalFlags(rootCmd)

	// Add version command
	rootCmd.AddCommand(version.NewVersionCommand(appCtx))

	version.AddVersionFlag(rootCmd)

	rootCmd.AddCommand(compute.NewComputeCmd(appCtx))

	rootCmd.AddCommand(identity.NewIdentityCmd(appCtx))

	rootCmd.AddCommand(database.NewDatabaseCmd(appCtx))

	rootCmd.AddCommand(network.NewNetworkCmd(appCtx))

	return rootCmd
}

// Execute runs the root command with the given context.
// It now returns an error instead of exiting directly.
func Execute(ctx context.Context) error {
	// Create a temporary root command for bootstrapping
	tempRoot := &cobra.Command{
		Use:          "ocloud",
		Short:        "Interact with Oracle Cloud Infrastructure",
		Long:         "",
		SilenceUsage: true,
	}

	flags.AddGlobalFlags(tempRoot)

	if err := setLogLevel(tempRoot); err != nil {
		return fmt.Errorf("setting log level: %w", err)
	}

	appCtx, err := InitializeAppContext(ctx, tempRoot)
	if err != nil {
		return fmt.Errorf("initializing app context: %w", err)
	}

	// Create the real root command with the ApplicationContext
	root := NewRootCmd(appCtx)

	// Switch to RunE for the root command
	root.RunE = func(cmd *cobra.Command, args []string) error {
		return cmd.Help() // The default behavior is to show help
	}

	// Execute the command
	if err := root.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("failed to execute root command: %w", err)
	}

	return nil
}
