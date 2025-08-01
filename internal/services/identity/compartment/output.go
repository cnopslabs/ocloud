package compartment

import (
	"github.com/cnopslabs/ocloud/internal/app"
	"github.com/cnopslabs/ocloud/internal/printer"
	"github.com/cnopslabs/ocloud/internal/services/util"
)

// PrintCompartmentsTable displays a table or JSON representation of compartments based on the provided configuration.
// It optionally includes pagination details and writes to the application's standard output or as structured JSON.
func PrintCompartmentsTable(compartments []Compartment, appCtx *app.ApplicationContext, pagination *util.PaginationInfo, useJSON bool) error {

	// Create a new printer that writes to the application's standard output.
	p := printer.New(appCtx.Stdout)

	// Adjust the pagination information if available
	if pagination != nil {
		util.AdjustPaginationInfo(pagination)
	}

	// If JSON output is requested, use the printer to marshal the response.
	if useJSON {
		// Special case for empty compartments list - return an empty object
		if len(compartments) == 0 && pagination == nil {
			return p.MarshalToJSON(struct{}{})
		}
		return util.MarshalDataToJSONResponse[Compartment](p, compartments, pagination)
	}

	if util.ValidateAndReportEmpty(compartments, pagination, appCtx.Stdout) {
		return nil
	}

	// Define table headers
	headers := []string{"Name", "ID"}

	// Create rows for the table
	rows := make([][]string, len(compartments))
	for i, c := range compartments {

		// Create a row for this compartment
		rows[i] = []string{
			c.Name,
			c.ID,
		}
	}

	// Print the table
	title := util.FormatColoredTitle(appCtx, "Compartments")
	p.PrintTable(title, headers, rows)

	util.LogPaginationInfo(pagination, appCtx)
	return nil
}

// PrintCompartmentsInfo displays information about a list of compartments in either JSON or formatted table output.
// It accepts a slice of Compartment, application context, pagination info, and a boolean to indicate JSON output.
// It adjusts pagination details, validates empty compartments, and logs pagination info post-output.
// Returns an error if JSON marshalling or output rendering fails.
func PrintCompartmentsInfo(compartments []Compartment, appCtx *app.ApplicationContext, pagination *util.PaginationInfo, useJSON bool) error {

	// Create a new printer that writes to the application's standard output.
	p := printer.New(appCtx.Stdout)

	// Adjust the pagination information if available
	if pagination != nil {
		util.AdjustPaginationInfo(pagination)
	}

	// If JSON output is requested, use the printer to marshal the response.
	if useJSON {
		// Special case for empty compartments list - return an empty object
		if len(compartments) == 0 && pagination == nil {
			return p.MarshalToJSON(struct{}{})
		}
		return util.MarshalDataToJSONResponse[Compartment](p, compartments, pagination)
	}

	if util.ValidateAndReportEmpty(compartments, pagination, appCtx.Stdout) {
		return nil
	}

	// Print each Compartment as a separate key-value table with a colored title.
	for _, compartment := range compartments {
		compartmentData := map[string]string{
			"Name":        compartment.Name,
			"ID":          compartment.ID,
			"Description": compartment.Description,
		}
		// Define ordered keys
		orderedKeys := []string{
			"Name", "ID", "Description",
		}

		title := util.FormatColoredTitle(appCtx, compartment.Name)

		// Call the printer method to render the key-value table for this instance.
		p.PrintKeyValues(title, compartmentData, orderedKeys)
	}

	util.LogPaginationInfo(pagination, appCtx)
	return nil
}
