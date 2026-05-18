package bastion

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionTypesForTarget_InstanceIncludesRDP(t *testing.T) {
	got := SessionTypesForTarget(TargetInstance)
	assert.Contains(t, got, TypeRDP, "Instance target should expose RDP as a session type")
	// Existing entries must still be present (no regression).
	assert.Contains(t, got, TypeSCP)
	assert.Contains(t, got, TypeSCPDownload)
	assert.Contains(t, got, TypeManagedSSH)
	assert.Contains(t, got, TypePortForwarding)
}

func TestSessionTypesForTarget_NonInstanceTargetsDoNotIncludeRDP(t *testing.T) {
	for _, tt := range []TargetType{TargetOKE, TargetDatabase, TargetLoadBalancer} {
		t.Run(string(tt), func(t *testing.T) {
			got := SessionTypesForTarget(tt)
			assert.NotContains(t, got, TypeRDP, "%s target must not expose RDP", tt)
		})
	}
}
