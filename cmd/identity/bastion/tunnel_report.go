package bastion

import (
	"errors"
	"time"

	"github.com/cnopslabs/ocloud/internal/logger"
	bastionSvc "github.com/cnopslabs/ocloud/internal/services/identity/bastion"
)

const (
	tunnelListenTimeout = 30 * time.Second
	tunnelProbeTimeout  = 15 * time.Second
)

// reportTunnel checks a freshly spawned tunnel end to end and tells the user what it found.
// The tunnel keeps running either way; a failure here usually means a network rule needs fixing.
func reportTunnel(localPort int, logFile string) {
	err := bastionSvc.CheckTunnel(localPort, logFile, tunnelListenTimeout, tunnelProbeTimeout)

	var unreachable *bastionSvc.TargetUnreachableError
	switch {
	case err == nil:
		logger.Logger.Info("Tunnel is ready: the bastion reached the target")
	case errors.As(err, &unreachable):
		logger.Logger.Info("Tunnel is up locally, but the bastion could not reach the target", "ssh", unreachable.Reason)
		logger.Logger.Info("Check that the target subnet's security list/NSG allows TCP ingress from the bastion's private endpoint IP on the target port, and that a service is listening on that port")
	case errors.Is(err, bastionSvc.ErrTunnelNotListening):
		logger.Logger.Info("Tunnel did not start listening on the local port; check the log", "port", localPort, "logs", logFile)
	default:
		logger.Logger.Info("Tunnel is listening, but the target's reachability could not be confirmed yet; check the log if your client can't connect", "logs", logFile)
	}
}
