package cmdcreate

import (
	"fmt"
	"os"

	"github.com/cnopslabs/ocloud/cmd/compute"
	computeoke "github.com/cnopslabs/ocloud/cmd/compute/oke"
	"github.com/cnopslabs/ocloud/cmd/configuration"
	"github.com/cnopslabs/ocloud/cmd/database"
	"github.com/cnopslabs/ocloud/cmd/identity"
	"github.com/cnopslabs/ocloud/cmd/network"
	"github.com/cnopslabs/ocloud/cmd/storage"
	"github.com/cnopslabs/ocloud/cmd/version"
	"github.com/cnopslabs/ocloud/internal/app"
	"github.com/cnopslabs/ocloud/internal/config/flags"
	"github.com/spf13/cobra"
)

// CreateRootCmd creates a root command with or without application context
// If appCtx is nil, only commands that don't need context are added
// If appCtx is not nil, all commands are added
func CreateRootCmd(appCtx *app.ApplicationContext) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "ocloud",
		Short:        "Interact with Oracle Cloud Infrastructure",
		Long:         "",
		SilenceUsage: true,
	}

	// Initialize global flags
	flags.AddGlobalFlags(rootCmd)

	// Add commands that don't need context
	rootCmd.AddCommand(version.NewVersionCommand())
	version.AddVersionFlag(rootCmd, os.Stdout)
	rootCmd.AddCommand(configuration.NewConfigCmd())
	rootCmd.AddCommand(computeoke.NewLegacyTokenCmd())

	// If appCtx is not nil, add commands that need context
	if appCtx != nil {
		rootCmd.AddCommand(compute.NewComputeCmd(appCtx))
		rootCmd.AddCommand(identity.NewIdentityCmd(appCtx))
		rootCmd.AddCommand(database.NewDatabaseCmd(appCtx))
		rootCmd.AddCommand(network.NewNetworkCmd(appCtx))
		rootCmd.AddCommand(storage.NewStorageCmd(appCtx))
	}

	return rootCmd
}

// CreateRootCmdWithoutContext creates a root command without application context
// This is used for commands that don't need a full context
func CreateRootCmdWithoutContext() *cobra.Command {
	rootCmd := CreateRootCmd(nil)

	addPlaceholderCommands(rootCmd)

	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}

	return rootCmd
}

// addPlaceholderCommands adds placeholder commands that will be displayed in help
// but will show a message about needing to initialize if they're actually run
func addPlaceholderCommands(rootCmd *cobra.Command) {
	commandTypes := []struct {
		use   string
		short string
	}{
		{"compute", "Explore OCI compute services"},
		{"identity", "Explore OCI identity services"},
		{"database", "Explore OCI Database services"},
		{"network", "Explore OCI network services"},
		{"storage", "Explore OCI Storage services"},
	}

	for _, cmdType := range commandTypes {
		cmd := &cobra.Command{
			Use:   cmdType.use,
			Short: cmdType.short,
			RunE: func(cmd *cobra.Command, args []string) error {
				return fmt.Errorf("this command requires application initialization")
			},
		}
		if cmdType.use == "compute" {
			// `compute oke token` runs without application context (see cmdutil.IsOKETokenCommand),
			// so the placeholder tree must contain the real token command.
			cmd.Aliases = []string{"comp"}
			okeCmd := &cobra.Command{Use: "oke", Short: "Explore OCI Kubernetes Engine (OKE)"}
			okeCmd.AddCommand(computeoke.NewTokenCmd())
			cmd.AddCommand(okeCmd)
		}
		rootCmd.AddCommand(cmd)
	}
}
