package bastion

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cnopslabs/ocloud/internal/app"
	"github.com/cnopslabs/ocloud/internal/logger"
	"github.com/cnopslabs/ocloud/internal/oci"
	ociInst "github.com/cnopslabs/ocloud/internal/oci/compute/instance"
	instSvc "github.com/cnopslabs/ocloud/internal/services/compute/instance"
	bastionSvc "github.com/cnopslabs/ocloud/internal/services/identity/bastion"
	"github.com/cnopslabs/ocloud/internal/services/util"
)

// connectInstance runs the flow for an Instance target.
func connectInstance(ctx context.Context, appCtx *app.ApplicationContext, svc *bastionSvc.Service,
	b bastionSvc.Bastion, sType SessionType) error {

	computeClient, err := oci.NewComputeClient(appCtx.Provider)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}
	networkClient, err := oci.NewNetworkClient(appCtx.Provider)
	if err != nil {
		return fmt.Errorf("creating network client: %w", err)
	}
	instanceAdapter := ociInst.NewAdapter(computeClient, networkClient)
	instService := instSvc.NewService(instanceAdapter, appCtx.Logger, appCtx.CompartmentID)

	instances, _, _, err := instService.FetchPaginatedInstances(ctx, 300, 0)
	if err != nil {
		return fmt.Errorf("list instances: %w", err)
	}

	if len(instances) == 0 {
		logger.Logger.Info("No instances found.")
		return nil
	}

	// TUI selection
	im := NewInstanceListModelFancy(instances)
	ip := tea.NewProgram(im, tea.WithContext(ctx))
	ires, err := ip.Run()
	if err != nil {
		return fmt.Errorf("instance selection TUI: %w", err)
	}
	chosen, ok := ires.(ResourceListModel)
	if !ok || chosen.Choice() == "" {
		return ErrAborted
	}

	pubKey, privKey, err := SelectSSHKeyPair(ctx)
	if err != nil {
		return err
	}

	var inst instSvc.Instance
	for _, it := range instances {
		if it.OCID == chosen.Choice() {
			inst = it
			break
		}
	}

	if ok, reason := svc.CanReach(ctx, b, inst.VcnID, inst.SubnetID); !ok {
		logger.Logger.Info("Bastion cannot reach selected instance", "reason", reason)
		return nil
	}

	logger.Logger.Info("Validated session on Bastion to Instance", "session_type", sType, "bastion_name", b.DisplayName, "bastion_id", b.OCID, "instance_name", inst.DisplayName)

	region, regErr := appCtx.Provider.Region()
	if regErr != nil {
		return fmt.Errorf("get region: %w", regErr)
	}

	switch sType {
	case TypeManagedSSH:
		sshUser, err := util.PromptString("Enter SSH username", "opc")
		if err != nil {
			return fmt.Errorf("read ssh username: %w", err)
		}
		sessID, err := svc.EnsureManagedSSHSession(ctx, b.OCID, inst.OCID, inst.PrimaryIP, sshUser, 22, pubKey, 0)
		if err != nil {
			return fmt.Errorf("ensure managed SSH: %w", err)
		}
		sshCmd := bastionSvc.BuildManagedSSHCommand(privKey, sessID, region, inst.PrimaryIP, sshUser)
		logger.Logger.Info("Executing", "command", sshCmd)
		return bastionSvc.RunShell(ctx, appCtx.Stdout, appCtx.Stderr, sshCmd)
	case TypePortForwarding:
		targetPort, err := util.PromptPort("Enter target port (service port on the instance)", 5901)
		if err != nil {
			return fmt.Errorf("read target port: %w", err)
		}

		localPort, err := promptPortWithPrivilegedWarning("Enter local port", targetPort)
		if err != nil {
			return fmt.Errorf("read local port: %w", err)
		}

		if util.IsLocalTCPPortInUse(localPort) {
			return fmt.Errorf("local port %d is already in use on 127.0.0.1; choose another port", localPort)
		}

		var sudoPassword string
		if localPort < 1024 {
			logger.Logger.Info("Validating sudo access for privileged port...")
			var err error
			sudoPassword, err = util.PromptPassword("Password")
			if err != nil {
				return fmt.Errorf("read password: %w", err)
			}
			if err := bastionSvc.ValidateSudoPassword(sudoPassword); err != nil {
				return fmt.Errorf("sudo validation failed: %w", err)
			}
			logger.Logger.Info("Sudo access validated successfully")
		}

		sessID, err := svc.EnsurePortForwardSession(ctx, b.OCID, inst.PrimaryIP, targetPort, pubKey)
		if err != nil {
			return fmt.Errorf("ensure port forward: %w", err)
		}
		sshTunnelArgs, err := bastionSvc.BuildPortForwardArgs(privKey, sessID, region, inst.PrimaryIP, localPort, targetPort)
		if err != nil {
			return fmt.Errorf("build args: %w", err)
		}

		var (
			pid     int
			logFile string
		)
		if localPort < 1024 {
			pid, logFile, err = bastionSvc.SpawnDetachedWithSudo(sshTunnelArgs, localPort, inst.PrimaryIP, sudoPassword)
		} else {
			pid, logFile, err = bastionSvc.SpawnDetached(sshTunnelArgs, localPort, inst.PrimaryIP)
		}
		if err != nil {
			return fmt.Errorf("spawn detached: %w", err)
		}
		logger.Logger.V(logger.Debug).Info("spawned tunnel", "pid", pid)

		tunnelInfo := bastionSvc.TunnelInfo{
			PID:       pid,
			LocalPort: localPort,
			TargetIP:  inst.PrimaryIP,
			StartedAt: time.Now(),
			LogFile:   logFile,
		}
		if err := bastionSvc.SaveTunnelState(tunnelInfo); err != nil {
			logger.Logger.Error(err, "failed to save tunnel state")
		}

		logger.Logger.Info("SSH tunnel process started, waiting for connection to be ready...")
		if err := bastionSvc.WaitForListen(localPort, 30*time.Second); err != nil {
			logger.Logger.Info("Tunnel verification timed out, but the tunnel may still be establishing in the background", "port", localPort)
			logger.Logger.Info("Check the tunnel status and logs if you experience connection issues")
		} else {
			logger.Logger.Info("Tunnel is ready and accepting connections")
		}

		logger.Logger.Info("SSH tunnel running in background",
			"local", fmt.Sprintf("127.0.0.1:%d", localPort),
			"target", fmt.Sprintf("%s:%d", inst.PrimaryIP, targetPort),
			"bastion_session", sessID,
			"logs", logFile)
		return nil
	case TypeRDP:
		return connectInstanceRDP(ctx, svc, b, inst, region, pubKey, privKey)
	default:
		return fmt.Errorf("unsupported session type: %s", sType)
	}
}

// connectInstanceRDP runs the RDP-over-bastion flow against a Windows instance.
// Internally this is a PORT_FORWARDING session pinned to remote port 3389 (RDP).
// The local port defaults to 3389 but is user-selectable; binding a privileged
// local port (<1024) triggers the same sudo flow used elsewhere.
func connectInstanceRDP(ctx context.Context, svc *bastionSvc.Service,
	b bastionSvc.Bastion, inst instSvc.Instance, region, pubKey, privKey string) error {

	const remoteRDPPort = 3389

	defaultLocalPort := remoteRDPPort
	localPort, err := promptPortWithPrivilegedWarning("Enter local port for RDP tunnel", defaultLocalPort)
	if err != nil {
		return fmt.Errorf("read port: %w", err)
	}

	if util.IsLocalTCPPortInUse(localPort) {
		return fmt.Errorf("local port %d is already in use on 127.0.0.1; choose another port", localPort)
	}

	var sudoPassword string
	if localPort < 1024 {
		logger.Logger.Info("Validating sudo access for privileged port...")
		var err error
		sudoPassword, err = util.PromptPassword("Password")
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		if err := bastionSvc.ValidateSudoPassword(sudoPassword); err != nil {
			return fmt.Errorf("sudo validation failed: %w", err)
		}
		logger.Logger.Info("Sudo access validated successfully")
	}

	sessID, err := svc.EnsurePortForwardSession(ctx, b.OCID, inst.PrimaryIP, remoteRDPPort, pubKey)
	if err != nil {
		return fmt.Errorf("ensure port forward: %w", err)
	}
	sshTunnelArgs, err := bastionSvc.BuildPortForwardArgs(privKey, sessID, region, inst.PrimaryIP, localPort, remoteRDPPort)
	if err != nil {
		return fmt.Errorf("build args: %w", err)
	}

	var (
		pid     int
		logFile string
	)
	if localPort < 1024 {
		pid, logFile, err = bastionSvc.SpawnDetachedWithSudo(sshTunnelArgs, localPort, inst.PrimaryIP, sudoPassword)
	} else {
		pid, logFile, err = bastionSvc.SpawnDetached(sshTunnelArgs, localPort, inst.PrimaryIP)
	}
	if err != nil {
		return fmt.Errorf("spawn detached: %w", err)
	}
	logger.Logger.V(logger.Debug).Info("spawned RDP tunnel", "pid", pid)

	tunnelInfo := bastionSvc.TunnelInfo{
		PID:       pid,
		LocalPort: localPort,
		TargetIP:  inst.PrimaryIP,
		StartedAt: time.Now(),
		LogFile:   logFile,
	}
	if err := bastionSvc.SaveTunnelState(tunnelInfo); err != nil {
		logger.Logger.Error(err, "failed to save tunnel state")
	}

	logger.Logger.Info("RDP tunnel process started, waiting for connection to be ready...")
	if err := bastionSvc.WaitForListen(localPort, 30*time.Second); err != nil {
		logger.Logger.Info("Tunnel verification timed out, but the tunnel may still be establishing in the background", "port", localPort)
		logger.Logger.Info("Check the tunnel status and logs if you experience connection issues")
	} else {
		logger.Logger.Info("Tunnel is ready and accepting connections")
	}

	logger.Logger.Info("RDP tunnel running in background",
		"local", fmt.Sprintf("127.0.0.1:%d", localPort),
		"target", fmt.Sprintf("%s:%d", inst.PrimaryIP, remoteRDPPort),
		"bastion_session", sessID,
		"logs", logFile)
	logger.Logger.Info("Connect with your RDP client:")
	logger.Logger.Info("  Windows", "command", fmt.Sprintf("mstsc /v:127.0.0.1:%d", localPort))
	logger.Logger.Info("  macOS  ", "command", fmt.Sprintf("open \"rdp://127.0.0.1:%d\"", localPort))
	logger.Logger.Info("  Linux  ", "command", fmt.Sprintf("xfreerdp /v:127.0.0.1:%d /u:<user>", localPort))
	return nil
}
