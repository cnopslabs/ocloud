package oke

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/cnopslabs/ocloud/internal/app"
)

// TestOKECommand tests the basic structure of the OKE command
func TestOKECommand(t *testing.T) {
	// Create a mock ApplicationContext
	appCtx := &app.ApplicationContext{}

	// Create a new OKE command
	cmd := NewOKECmd(appCtx)

	// Test that the OKE command is properly configured
	assert.Equal(t, "oke", cmd.Use)
	assert.Equal(t, "Manage OCI Kubernetes Engine (OKE)", cmd.Short)
	assert.Equal(t, "Manage Oracle Cloud Infrastructure Kubernetes Engine (OKE) clusters and node pools.\n\nThis command allows you to list all clusters in a compartment or find specific clusters by name pattern. For each cluster, you can view detailed information including Kubernetes version, endpoint, and associated node pools.", cmd.Long)
	assert.Equal(t, "  ocloud compute oke list\n  ocloud compute oke list --json\n  ocloud compute oke find myoke\n  ocloud compute oke find myoke --json", cmd.Example)
	assert.True(t, cmd.SilenceUsage)
	assert.True(t, cmd.SilenceErrors)

	// Test that the subcommands are added
	subCmds := cmd.Commands()
	assert.Equal(t, 2, len(subCmds), "oke command should have 2 subcommands")

	// Check that the list subcommand is present
	listCmd := findSubCommand(subCmds, "list")
	assert.NotNil(t, listCmd, "oke command should have list subcommand")

	// Check that the find subcommand is present
	findCmd := findSubCommand(subCmds, "find")
	assert.NotNil(t, findCmd, "oke command should have find subcommand")
}

// findSubCommand is a helper function to find a subcommand by name
func findSubCommand(cmds []*cobra.Command, name string) *cobra.Command {
	for _, cmd := range cmds {
		if cmd.Name() == name {
			return cmd
		}
	}
	return nil
}
