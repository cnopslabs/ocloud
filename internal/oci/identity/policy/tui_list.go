package policy

import (
	"fmt"

	domain "github.com/cnopslabs/ocloud/internal/domain/identity"
	"github.com/cnopslabs/ocloud/internal/tui"
)

// NewPoliciesListModel builds a TUI list for policies.
func NewPoliciesListModel(p []domain.Policy) tui.Model {
	return tui.NewModel("Policies", p, func(p domain.Policy) tui.ResourceItemData {
		return tui.ResourceItemData{
			ID:          p.ID,
			Title:       p.Name,
			Description: fmt.Sprint(p.Description, "  •  ", p.TimeCreated.Format("2006-01-02")),
		}
	})
}
