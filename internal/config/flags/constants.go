// Package flags define flag types and domain-specific flag collections for the CLI.
package flags

// FlagNames defines the string constants for flag names
const (
	FlagNameLogLevel           = "log-level"
	FlagNameDebug              = "debug"
	FlagNameTenancyID          = "tenancy-id"
	FlagNameTenancyName        = "tenancy-name"
	FlagNameCompartment        = "compartment"
	FlagNameCreate             = "create"
	FlagNameType               = "type"
	FlagNameBastionID          = "bastion-id"
	FlagNameTargetIP           = "target-ip"
	FlagNameTTL                = "ttl"
	FlagNamePrivateKey         = "private-key"
	FlagNamePublicKey          = "public-key"
	FlagNameInstanceID         = "instance-id"
	FlagNameUser               = "user"
	FlagNameLocalFwPort        = "local-fw-port"
	FlagNameHostFwPort         = "host-fw-port"
	FlagNameHelp               = "help"
	FlagNameColor              = "color"
	FlagNameDisableConcurrency = "disable-concurrency"
	FlagNameLimit              = "limit"
	FlagNamePage               = "page"
	FlagNameJSON               = "json"
	FlagNameVersion            = "version"
	FlagNameAllInformation     = "all"
	FlagNameSort               = "sort"
	FlagNameRealm              = "realm"
	FlagNameFilter             = "filter"
)

// FlagShorthands defines single-character aliases for flags
const (
	FlagShortTenancyID          = "t"
	FlagShortCompartment        = "c"
	FlagShortCreate             = "r"
	FlagShortType               = "y"
	FlagShortBastionID          = "b"
	FlagShortTargetIP           = "i"
	FlagShortTTL                = "m"
	FlagShortPrivateKey         = "a"
	FlagShortPublicKey          = "e"
	FlagShortInstanceID         = "o"
	FlagShortUser               = "u"
	FlagShortLocalFwPort        = "w"
	FlagShortHostFwPort         = "f"
	FlagShortHelp               = "h"
	FlagShortDebug              = "d"
	FlagShortDisableConcurrency = "x"
	FlagShortLimit              = "m"
	FlagShortPage               = "p"
	FlagShortJSON               = "j"
	FlagShortVersion            = "v"
	FlagShortAllInformation     = "A"
	FlagShortSort               = "s"
	FlagShortRealm              = "r"
	FlagShortFilter             = "f"
)

// FlagDescriptions contains help text for flags
const (
	FlagDescLogLevel           = "Set the log verbosity debug,"
	FlagDescDebug              = "Enable debug logging"
	FlagDescCreate             = "Create a resource"
	FlagDescType               = "Resource type"
	FlagDescBastionID          = "Bastion OCID"
	FlagDescTargetIP           = "Target IP address"
	FlagDescTTL                = "TTL in minutes"
	FlagDescPrivateKey         = "Private key file path"
	FlagDescPublicKey          = "Public key file path"
	FlagDescInstanceID         = "Instance OCID"
	FlagDescUser               = "User name"
	FlagDescLocalFwPort        = "Local port forwarded to the instance"
	FlagDescHostFwPort         = "Host port forwarded to the instance"
	FlagDescTenancyID          = "OCI tenancy OCID"
	FlagDescTenancyName        = "Tenancy name"
	FlagDescCompartment        = "OCI compartment name"
	FlagDescHelp               = "help for ocloud (shorthand: -h)"
	FlagDescDisableConcurrency = "Disable concurrency when fetching instance details (use -x to disable concurrency if rate limit is reached for large result sets)"
	FlagDescLimit              = "Maximum number of records to display per page"
	FlagDescPage               = "Page number to display"
	FlagDescJSON               = "Output information in JSON format"
	FlagDescVersion            = "Print the version number of ocloud CLI"
	FlagDescAllInformation     = "Show all information"
	FlagDescSort               = "Sort results by field (name or cidr)"
	FlagDescRealm              = "Filter by realm (e.g., OC1, OC2, OC2)"
	FlagDescFilter             = "Filter regions by prefix (e.g., us, eu, ap)"
)

// Flag values and defaults
const (
	FlagValueTrue     = "true"
	FlagValueInfo     = "info"
	FlagValueHelpMode = "help-mode"
)

// Flag prefixes and special strings
const (
	FlagPrefixShortHelp               = "-h"
	FlagPrefixLongHelp                = "--help"
	FlagPrefixColor                   = "--color"
	FlagPrefixDebug                   = "--debug"
	FlagPrefixShortDebug              = "-d"
	FlagPrefixDisableConcurrency      = "--disable-concurrency"
	FlagPrefixShortDisableConcurrency = "-x"
	FlagPrefixVersion                 = "--version"
	FlagPrefixShortVersion            = "-v"
	CobraAnnotationKey                = "cobra_annotation_flag_set_by_cobra"
)

// Environment variables
const (
	EnvOCITenancy     = "OCI_CLI_TENANCY"
	EnvOCITenancyName = "OCI_TENANCY_NAME"
	EnvOCICompartment = "OCI_COMPARTMENT"
	EnvOCIRegion      = "OCI_REGION"
)
