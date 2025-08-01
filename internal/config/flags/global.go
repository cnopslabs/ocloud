// Package flags define flag types and domain-specific flag collections for the CLI.
package flags

import (
	"github.com/cnopslabs/ocloud/internal/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Global flags
var (
	LogLevelFlag = StringFlag{
		Name:    FlagNameLogLevel,
		Default: FlagValueInfo,
		Usage:   FlagDescLogLevel,
	}

	DebugFlag = BoolFlag{
		Name:      FlagNameDebug,
		Shorthand: FlagShortDebug,
		Default:   false,
		Usage:     FlagDescDebug,
	}

	ColorFlag = BoolFlag{
		Name:    FlagNameColor,
		Default: false,
		Usage:   logger.ColoredOutputMsg,
	}

	TenancyIDFlag = StringFlag{
		Name:      FlagNameTenancyID,
		Shorthand: FlagShortTenancyID,
		Default:   "",
		Usage:     FlagDescTenancyID,
	}

	TenancyNameFlag = StringFlag{
		Name:    FlagNameTenancyName,
		Default: "",
		Usage:   FlagDescTenancyName,
	}

	CompartmentFlag = StringFlag{
		Name:      FlagNameCompartment,
		Shorthand: FlagShortCompartment,
		Default:   "",
		Usage:     FlagDescCompartment,
	}

	DisableConcurrencyFlag = BoolFlag{
		Name:      FlagNameDisableConcurrency,
		Shorthand: FlagShortDisableConcurrency,
		Default:   false,
		Usage:     FlagDescDisableConcurrency,
	}

	HelpFlag = BoolFlag{
		Name:      FlagNameHelp,
		Shorthand: FlagShortHelp,
		Default:   false,
		Usage:     FlagDescHelp,
	}
	JSONFlag = BoolFlag{
		Name:      FlagNameJSON,
		Shorthand: FlagShortJSON,
		Default:   false,
		Usage:     FlagDescJSON,
	}
)

// globalFlags is a slice of all global flags for batch registration
var globalFlags = []Flag{
	LogLevelFlag,
	DebugFlag,
	ColorFlag,
	TenancyIDFlag,
	TenancyNameFlag,
	CompartmentFlag,
	DisableConcurrencyFlag,
	HelpFlag,
	JSONFlag,
}

// AddGlobalFlags adds all global flags to the given command
func AddGlobalFlags(cmd *cobra.Command) {
	// Add global flags as persistent flags
	for _, f := range globalFlags {
		f.Apply(cmd.PersistentFlags())
	}

	// Set annotation for a help flag
	_ = cmd.PersistentFlags().SetAnnotation(FlagNameHelp, CobraAnnotationKey, []string{FlagValueTrue})

	// Bind flags to viper for configuration
	_ = viper.BindPFlag(FlagNameTenancyID, cmd.PersistentFlags().Lookup(FlagNameTenancyID))
	_ = viper.BindPFlag(FlagNameTenancyName, cmd.PersistentFlags().Lookup(FlagNameTenancyName))
	_ = viper.BindPFlag(FlagNameCompartment, cmd.PersistentFlags().Lookup(FlagNameCompartment))

	// allow ENV overrides, e.g., OCI_CLI_TENANCY, OCI_TENANCY_NAME, OCI_COMPARTMENT
	viper.SetEnvPrefix("OCI")
	viper.AutomaticEnv()
}
