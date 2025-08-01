package util

import (
	"fmt"
	"github.com/cnopslabs/ocloud/internal/app"
	"github.com/cnopslabs/ocloud/internal/logger"
	"io"
)

// LogPaginationInfo logs pagination information if available and prints it to the output.
func LogPaginationInfo(pagination *PaginationInfo, appCtx *app.ApplicationContext) {
	// Log pagination information if available
	if pagination != nil {
		// Determine if there's a next page
		hasNextPage := pagination.NextPageToken != ""

		// Log pagination information at the INFO level
		appCtx.Logger.Info("--- Pagination Information ---",
			"page", pagination.CurrentPage,
			"records", fmt.Sprintf("%d", pagination.TotalCount),
			"limit", pagination.Limit,
			"nextPage", hasNextPage)

		// Print pagination information to the output if stdout is available
		if appCtx.Stdout != nil {
			fmt.Fprintf(appCtx.Stdout, "Page %d | Total: %d\n", pagination.CurrentPage, pagination.TotalCount)
		}

		// Add debug logs for navigation hints
		if pagination.CurrentPage > 1 {
			logger.LogWithLevel(appCtx.Logger, 2, "Pagination navigation",
				"action", "previous page",
				"page", pagination.CurrentPage-1,
				"limit", pagination.Limit)
		}

		// Check if there are more pages after the current page
		// The most direct way to determine if there are more pages is to check if there's a next page token
		if pagination.NextPageToken != "" {
			logger.LogWithLevel(appCtx.Logger, 2, "Pagination navigation",
				"action", "next page",
				"page", pagination.CurrentPage+1,
				"limit", pagination.Limit)
		}
	}
}

// AdjustPaginationInfo adjusts the pagination information to ensure that the total count
// is correctly displayed. It calculates the total records displayed so far and updates
// the TotalCount field of the pagination object to match this value.
func AdjustPaginationInfo(pagination *PaginationInfo) {
	// Calculate the total records displayed so far
	totalRecordsDisplayed := pagination.CurrentPage * pagination.Limit
	if totalRecordsDisplayed > pagination.TotalCount {
		totalRecordsDisplayed = pagination.TotalCount
	}

	// Update the total count to match the total records displayed so far
	// This ensures that on page 1 we show 20, on page 2 we show 40, on page 3 we show 60, etc.
	pagination.TotalCount = totalRecordsDisplayed
}

// ValidateAndReportEmpty handles the case when a generic list is empty and provides pagination hints.
func ValidateAndReportEmpty[T any](items []T, pagination *PaginationInfo, out io.Writer) bool {
	if len(items) > 0 {
		return false
	}
	fmt.Fprintf(out, "No Items found.\n")
	if pagination != nil && pagination.TotalCount > 0 {
		fmt.Fprintf(out, "Page %d is empty. Total records: %d\n", pagination.CurrentPage, pagination.TotalCount)
		if pagination.CurrentPage > 1 {
			fmt.Fprintf(out, "Try a lower page number (e.g., --page %d)\n", pagination.CurrentPage-1)
		}
	}
	return true
}
