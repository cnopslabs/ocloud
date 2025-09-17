package policy

import (
	"fmt"

	"github.com/cnopslabs/ocloud/internal/domain"
	"github.com/cnopslabs/ocloud/internal/tui/listx"
)

// NewPoliciesListModel builds a TUI list for policies.
func NewPoliciesListModel(p []domain.Policy) listx.Model {
	return listx.NewModel("Policies", p, func(p domain.Policy) listx.ResourceItemData {
		return listx.ResourceItemData{
			ID:          p.ID,
			Title:       p.Name,
			Description: fmt.Sprint(p.Description, "  •  ", p.TimeCreated.Format("2006-01-02")),
		}
	})
}
