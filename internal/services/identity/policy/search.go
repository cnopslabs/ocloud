package policy

import (
	"context"
	"fmt"

	"github.com/cnopslabs/ocloud/internal/app"
	"github.com/cnopslabs/ocloud/internal/logger"
	"github.com/cnopslabs/ocloud/internal/oci/identity/policy"
)

func SearchPolicies(appCtx *app.ApplicationContext, search string, useJSON bool, ocid string) error {
	ctx := context.Background()
	policyAdapter := policy.NewAdapter(appCtx.IdentityClient)

	// Create the application service, injecting the adapter.
	service := NewService(policyAdapter, appCtx.Logger, ocid)

	matchedPolicies, err := service.FuzzySearch(ctx, search)
	if err != nil {
		return fmt.Errorf("finding matched policies: %w", err)
	}
	err = PrintPolicyInfo(matchedPolicies, appCtx, nil, useJSON)
	if err != nil {
		return fmt.Errorf("printing matched policies: %w", err)
	}

	logger.LogWithLevel(logger.CmdLogger, logger.Info, "Found matching policies", "search", search, "matched", len(matchedPolicies))
	return nil
}
