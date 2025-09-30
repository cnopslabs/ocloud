package compartment

import (
	"fmt"

	domain "github.com/cnopslabs/ocloud/internal/domain/identity"
	"github.com/cnopslabs/ocloud/internal/tui"
)

// NewPoliciesListModel builds a TUI list for policies.
func NewPoliciesListModel(c []domain.Compartment) tui.Model {
	return tui.NewModel("Compartments", c, func(c domain.Compartment) tui.ResourceItemData {
		return tui.ResourceItemData{
			ID:          c.OCID,
			Title:       c.DisplayName,
			Description: fmt.Sprint(c.LifecycleState, "  •  ", c.Description),
		}
	})
}
