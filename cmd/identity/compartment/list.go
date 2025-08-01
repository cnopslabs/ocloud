package compartment

import (
	paginationFlags "github.com/cnopslabs/ocloud/cmd/flags"
	"github.com/cnopslabs/ocloud/internal/app"
	"github.com/cnopslabs/ocloud/internal/config/flags"
	"github.com/cnopslabs/ocloud/internal/logger"
	"github.com/cnopslabs/ocloud/internal/services/identity/compartment"
	"github.com/spf13/cobra"
)

// Long description for the list command
var listLong = `
List all Compartments in the specified tenancy or compartment with pagination support.

This command displays information about compartments in the current tenancy.
By default, it shows basic compartment information such as name, ID, and description.

The output is paginated, with a default limit of 20 compartments per page. You can navigate
through pages using the --page flag and control the number of compartments per page with
the --limit flag.

Additional Information:
- Use --json (-j) to output the results in JSON format
- The command shows all available compartments in the tenancy
`

// Examples for the list command
var listExamples = `
  # List all compartments with default pagination (20 per page)
  ocloud identity compartment list

  # List compartments with custom pagination (10 per page, page 2)
  ocloud identity compartment list --limit 10 --page 2

  # List compartments and output in JSON format
  ocloud identity compartment list --json

  # List compartments with custom pagination and JSON output
  ocloud identity compartment list --limit 5 --page 3 --json
`

// NewListCmd creates a new Cobra command for listing compartments in a specified tenancy or compartment.
// It supports pagination and optional JSON output.
func NewListCmd(appCtx *app.ApplicationContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "list",
		Aliases:       []string{"l"},
		Short:         "List all Compartments in the specified tenancy or compartment",
		Long:          listLong,
		Example:       listExamples,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunListCommand(cmd, appCtx)
		},
	}
	// Add flags specific to the list command
	paginationFlags.LimitFlag.Add(cmd)
	paginationFlags.PageFlag.Add(cmd)

	return cmd

}

// RunListCommand handles the execution of the list command
func RunListCommand(cmd *cobra.Command, appCtx *app.ApplicationContext) error {
	// Get pagination parameters
	limit := flags.GetIntFlag(cmd, flags.FlagNameLimit, paginationFlags.FlagDefaultLimit)
	page := flags.GetIntFlag(cmd, flags.FlagNamePage, paginationFlags.FlagDefaultPage)
	useJSON := flags.GetBoolFlag(cmd, flags.FlagNameJSON, false)

	// Use LogWithLevel to ensure debug logs work with shorthand flags
	logger.LogWithLevel(logger.CmdLogger, 1, "Running compartment list command in", "compartment", appCtx.CompartmentName, "json", useJSON)
	return compartment.ListCompartments(appCtx, useJSON, limit, page)
}
