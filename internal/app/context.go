package app

import (
	"context"
	"fmt"
	"github.com/cnopslabs/ocloud/internal/oci"
	"io"
	"os"

	"github.com/go-logr/logr"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cnopslabs/ocloud/internal/config"
	"github.com/cnopslabs/ocloud/internal/config/flags"
	"github.com/cnopslabs/ocloud/internal/logger"
)

// ApplicationContext represents the application with all its clients, configuration, and resolved IDs.
// It holds all the components needed for command execution.
type ApplicationContext struct {
	Provider          common.ConfigurationProvider
	IdentityClient    identity.IdentityClient
	TenancyID         string
	TenancyName       string
	CompartmentName   string
	CompartmentID     string
	Logger            logr.Logger
	EnableConcurrency bool
	Stdout            io.Writer
	Stderr            io.Writer
}

// InitApp initializes the application context, setting up configuration, clients, logging, and determineConcurrencyStatus settings.
// Returns an ApplicationContext instance and an error if initialization fails.
func InitApp(ctx context.Context, cmd *cobra.Command) (*ApplicationContext, error) {
	logger.CmdLogger.Info("Initializing application")

	provider := config.LoadOCIConfig()

	identityClient, err := oci.NewIdentityClient(provider)
	if err != nil {
		return nil, err
	}

	configureClientRegion(identityClient)

	enableConcurrency := determineConcurrencyStatus(cmd)

	appCtx := &ApplicationContext{
		Provider:          provider,
		IdentityClient:    identityClient,
		CompartmentName:   viper.GetString(flags.FlagNameCompartment),
		Logger:            logger.CmdLogger,
		EnableConcurrency: enableConcurrency,
	}
	// Set the standard writers for the application's lifetime.
	appCtx.Stdout = os.Stdout
	appCtx.Stderr = os.Stderr

	if err := resolveTenancyAndCompartment(ctx, cmd, appCtx); err != nil {
		return nil, fmt.Errorf("resolving tenancy and compartment: %w", err)
	}

	return appCtx, nil
}

// configureClientRegion checks the `OCI_REGION` environment variable and overrides the client's region if it is set.
func configureClientRegion(client identity.IdentityClient) {
	if region, ok := os.LookupEnv(flags.EnvOCIRegion); ok {
		client.SetRegion(region)
		logger.LogWithLevel(logger.CmdLogger, 3, "overriding region from env", "region", region)
	}
}

// determineConcurrencyStatus determines whether determineConcurrencyStatus is enabled based on command flags and specific CLI arguments.
// Returns true if determineConcurrencyStatus is enabled, or false if explicitly disabled via flags or defaults to enabled.
func determineConcurrencyStatus(cmd *cobra.Command) bool {
	disable := flags.GetBoolFlag(cmd, flags.FlagNameDisableConcurrency, false)
	explicit := cmd.Flags().Changed(flags.FlagNameDisableConcurrency)

	if explicit {
		return !disable // Invert the value since the flag is "disable-determineConcurrencyStatus"
	}

	for _, arg := range os.Args {
		if arg == flags.FlagPrefixShortDisableConcurrency || arg == flags.FlagPrefixDisableConcurrency {
			return false
		}
	}

	return true // default to enabled
}

// resolveTenancyAndCompartment resolves the tenancy ID, tenancy name, and compartment ID for the application context.
// It uses various sources such as CLI flags, environment variables, mapping files, and OCI configuration.
// Updates the provided ApplicationContext with the resolved IDs and names. Returns an error if resolution fails.
func resolveTenancyAndCompartment(ctx context.Context, cmd *cobra.Command, appCtx *ApplicationContext) error {
	tenancyID, err := resolveTenancyID(cmd)
	if err != nil {
		return fmt.Errorf("could not resolve tenancy ID: %w", err)
	}
	appCtx.TenancyID = tenancyID

	if name := resolveTenancyName(cmd, appCtx.TenancyID); name != "" {
		appCtx.TenancyName = name
	}

	compID, err := resolveCompartmentID(ctx, appCtx)
	if err != nil {
		return fmt.Errorf("could not resolve compartment ID: %w", err)
	}
	appCtx.CompartmentID = compID

	return nil
}

// resolveTenancyID resolves the tenancy OCID from various sources in order of precedence:
// 1. Command line flag
// 2. Environment variable
// 3. Tenancy name lookup (if tenancy name is provided)
// 4. OCI config file
// Returns the tenancy ID or an error if it cannot be resolved.
func resolveTenancyID(cmd *cobra.Command) (string, error) {
	// Check if tenancy ID is provided as a flag
	if cmd.Flags().Changed(flags.FlagNameTenancyID) {
		tenancyID := viper.GetString(flags.FlagNameTenancyID)
		logger.LogWithLevel(logger.CmdLogger, 3, "using tenancy OCID from flag", "tenancyID", tenancyID)
		return tenancyID, nil
	}

	// Check if tenancy ID is provided as an environment variable
	if envTenancy := os.Getenv(flags.EnvOCITenancy); envTenancy != "" {
		logger.LogWithLevel(logger.CmdLogger, 3, "using tenancy OCID from env", "tenancyID", envTenancy)
		viper.Set(flags.FlagNameTenancyID, envTenancy)
		return envTenancy, nil
	}

	// Check if the tenancy name is provided as an environment variable
	if envTenancyName := os.Getenv(flags.EnvOCITenancyName); envTenancyName != "" {
		lookupID, err := config.LookupTenancyID(envTenancyName)
		if err != nil {
			// Log the error but continue with the next method of resolving the tenancy ID
			logger.LogWithLevel(logger.CmdLogger, 3, "could not look up tenancy ID for tenancy name, continuing with other methods", "tenancyName", envTenancyName, "error", err)
			// Add a more detailed message about how to set up the mapping file
			logger.LogWithLevel(logger.CmdLogger, 3, "To set up tenancy mapping, create a YAML file at ~/.oci/tenancy-map.yaml or set the OCI_TENANCY_MAP_PATH environment variable. The file should contain entries mapping tenancy names to OCIDs. Example:\n- environment: prod\n  tenancy: mytenancy\n  tenancy_id: ocid1.tenancy.oc1..aaaaaaaabcdefghijklmnopqrstuvwxyz\n  realm: oc1\n  compartments: mycompartment\n  regions: us-ashburn-1")
		} else {
			logger.LogWithLevel(logger.CmdLogger, 3, "using tenancy OCID for name", "tenancyName", envTenancyName, "tenancyID", lookupID)
			viper.Set(flags.FlagNameTenancyID, lookupID)
			return lookupID, nil
		}
	}

	// Load from an OCI config file as a last resort
	tenancyID, err := config.GetTenancyOCID()
	if err != nil {
		return "", fmt.Errorf("could not load tenancy OCID: %w", err)
	}
	logger.LogWithLevel(logger.CmdLogger, 3, "using tenancy OCID from config file", "tenancyID", tenancyID)
	viper.Set(flags.FlagNameTenancyID, tenancyID)

	return tenancyID, nil
}

// resolveTenancyName resolves the tenancy name from various sources in order of precedence:
// 1. Command line flag
// 2. Environment variable
// 3. Tenancy mapping file lookup (using tenancy ID)
// Returns the tenancy name or an empty string if it cannot be resolved.
func resolveTenancyName(cmd *cobra.Command, tenancyID string) string {

	// Check if the tenancy name is provided as a flag
	if cmd.Flags().Changed(flags.FlagNameTenancyName) {
		tenancyName := viper.GetString(flags.FlagNameTenancyName)
		logger.LogWithLevel(logger.CmdLogger, 3, "using tenancy name from flag", "tenancyName", tenancyName)
		return tenancyName
	}

	// Check if the tenancy name is provided as an environment variable
	if envTenancyName := os.Getenv(flags.EnvOCITenancyName); envTenancyName != "" {
		logger.LogWithLevel(logger.CmdLogger, 3, "using tenancy name from env", "tenancyName", envTenancyName)
		viper.Set(flags.FlagNameTenancyName, envTenancyName)
		return envTenancyName
	}

	// Try to find a tenancy name from a mapping file if available
	tenancies, err := config.LoadTenancyMap()
	if err == nil {
		for _, env := range tenancies {
			if env.TenancyID == tenancyID {
				logger.LogWithLevel(logger.CmdLogger, 3, "found tenancy name from mapping file", "tenancyName", env.Tenancy)
				viper.Set(flags.FlagNameTenancyName, env.Tenancy)
				return env.Tenancy
			}
		}
	}

	return ""
}

// resolveCompartmentID returns the OCID of the compartment whose name matches
// `compartmentName` under the given tenancy. It searches all active compartments
// in the tenancy subtree.
func resolveCompartmentID(ctx context.Context, appCtx *ApplicationContext) (string, error) {
	compartmentName := appCtx.CompartmentName
	idClient := appCtx.IdentityClient
	tenancyOCID := appCtx.TenancyID

	// If the compartment name is not set, use tenancy ID as fallback
	if compartmentName == "" {
		logger.LogWithLevel(logger.CmdLogger, 3, "compartment name not set, using tenancy ID as fallback", "tenancyID", tenancyOCID)
		return tenancyOCID, nil
	}

	// prepare the base request
	req := identity.ListCompartmentsRequest{
		CompartmentId:          &tenancyOCID,
		AccessLevel:            identity.ListCompartmentsAccessLevelAccessible,
		LifecycleState:         identity.CompartmentLifecycleStateActive,
		CompartmentIdInSubtree: common.Bool(true),
	}

	// paginate through results; stop when OpcNextPage is nil
	pageToken := ""
	for {
		if pageToken != "" {
			req.Page = common.String(pageToken)
		}

		resp, err := idClient.ListCompartments(ctx, req)
		if err != nil {
			return "", fmt.Errorf("listing compartments: %w", err)
		}

		// scan each compartment summary for a name match
		for _, comp := range resp.Items {
			if comp.Name != nil && *comp.Name == compartmentName {
				return *comp.Id, nil
			}
		}

		// if there's no next page, we're done searching
		if resp.OpcNextPage == nil {
			break
		}
		pageToken = *resp.OpcNextPage
	}

	return "", fmt.Errorf("compartment %q not found under tenancy %s", compartmentName, tenancyOCID)
}
