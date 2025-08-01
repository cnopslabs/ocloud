package compartment

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cnopslabs/ocloud/internal/app"
)

// TestFindCommand tests the basic structure of the find command
func TestFindCommand(t *testing.T) {
	// Create a mock ApplicationContext
	appCtx := &app.ApplicationContext{}

	// Create a new find command
	cmd := NewFindCmd(appCtx)

	// Test that the find command is properly configured
	assert.Equal(t, "find [pattern]", cmd.Use)
	assert.Equal(t, []string{"f"}, cmd.Aliases)
	assert.Equal(t, "Find compartment by name pattern", cmd.Short)
	assert.Equal(t, findLong, cmd.Long)
	assert.Equal(t, findExamples, cmd.Example)
	assert.True(t, cmd.SilenceUsage)
	assert.True(t, cmd.SilenceErrors)
	// Verify that the command requires exactly one argument
	assert.NotNil(t, cmd.Args)

	// Note: The JSON flag is a global flag and is not directly added to the command in the find.go file.
	// It's added at a higher level in the command hierarchy.
}
