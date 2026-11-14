package cmdutil

import (
	"os"
)

// IsNoContextCommand checks if a command doesn't need a full application context
func IsNoContextCommand() bool {
	args := os.Args
	if len(args) < 2 {
		return true
	}

	// Commands that don't need context
	noContextCommands := map[string]bool{
		"version": true,
		"config":  true,
		"conf":    true, // alias of config
	}

	// Flags that don't need context
	noContextFlags := map[string]bool{
		"--version": true,
		"-v":        true,
	}

	if noContextCommands[args[1]] || IsOKETokenCommand() {
		return true
	}

	for _, arg := range args[1:] {
		if noContextFlags[arg] {
			return true
		}
	}

	return false
}

// IsRootCommandWithoutSubcommands checks if the command being executed is the root command without any subcommands or flags
func IsRootCommandWithoutSubcommands() bool {
	args := os.Args
	return len(args) == 1
}

// IsOKETokenCommand reports whether the invocation is the kubectl exec plugin,
// `ocloud compute oke token` (or `comp`) or the deprecated `ocloud oke-token`.
// It must not build the application context: kubectl calls it often and reads
// only the ExecCredential JSON from stdout.
func IsOKETokenCommand() bool {
	args := os.Args
	if len(args) >= 2 && args[1] == "oke-token" {
		return true
	}
	return len(args) >= 4 && (args[1] == "compute" || args[1] == "comp") && args[2] == "oke" && args[3] == "token"
}
