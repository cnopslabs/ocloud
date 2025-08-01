package subnet

import (
	"github.com/cnopslabs/ocloud/internal/app"
	"github.com/cnopslabs/ocloud/internal/config/flags"
	"github.com/cnopslabs/ocloud/internal/logger"
	"github.com/cnopslabs/ocloud/internal/services/network/subnet"
	"github.com/spf13/cobra"
)

// Long description for the find command
var findLong = `
Find Subnets in the specified tenancy or compartment that match the given pattern.

This command searches for subnets whose names match the specified pattern.
By default, it shows detailed subnet information such as name, ID, CIDR block,
and whether public IP addresses are allowed for all matching subnets.

The search is performed using fuzzy matching, which means it will find subnets
even if the pattern is only partially matched. The search is case-insensitive.

Additional Information:
- Use --json (-j) to output the results in JSON format
- The command searches across all available subnets in the compartment
`

// Examples for the find command
var findExamples = `
  # Find subnets with names containing "prod"
  ocloud network subnet find prod

  # Find subnets with names containing "dev" and output in JSON format
  ocloud network subnet find dev --json

  # Find subnets with names containing "test" (case-insensitive)
  ocloud network subnet find test
`

// NewFindCmd creates a new command for finding subnets by name pattern
func NewFindCmd(appCtx *app.ApplicationContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "find [pattern]",
		Aliases:       []string{"f"},
		Short:         "Find Subnets by name pattern",
		Long:          findLong,
		Example:       findExamples,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunFindCommand(cmd, args, appCtx)
		},
	}

	return cmd
}

// RunFindCommand handles the execution of the find command
func RunFindCommand(cmd *cobra.Command, args []string, appCtx *app.ApplicationContext) error {
	namePattern := args[0]
	useJSON := flags.GetBoolFlag(cmd, flags.FlagNameJSON, false)

	// Use LogWithLevel to ensure debug logs work with shorthand flags
	logger.LogWithLevel(logger.CmdLogger, 1, "Running subnet find command", "pattern", namePattern, "json", useJSON)
	return subnet.FindSubnets(appCtx, namePattern, useJSON)
}
