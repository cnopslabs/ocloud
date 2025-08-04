package setup

import (
	appConfig "github.com/cnopslabs/ocloud/internal/config"
	"github.com/go-logr/logr"
)

// Service provides operations and functionalities related to tenancy mapping information.
type Service struct {
	logger logr.Logger
}

// TenancyMappingResult represents the result of loading and filtering tenancy mappings.
type TenancyMappingResult struct {
	Mappings []appConfig.MappingsFile
}
