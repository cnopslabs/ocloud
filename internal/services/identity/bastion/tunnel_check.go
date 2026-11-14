package bastion

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cnopslabs/ocloud/internal/config/flags"
)

// ErrTunnelNotListening means the local end of the tunnel never started listening.
var ErrTunnelNotListening = errors.New("tunnel is not listening on the local port")

// ErrTunnelUnconfirmed means the local port is up, but the bastion neither confirmed
// nor rejected the forwarded connection before the probe timed out.
var ErrTunnelUnconfirmed = errors.New("could not confirm the target is reachable through the tunnel")

// TargetUnreachableError means the bastion rejected the forwarded connection,
// typically because a security list/NSG blocks the bastion or nothing listens on the target port.
type TargetUnreachableError struct {
	Reason string // ssh's failure line, e.g. "channel 2: open failed: connect failed: Connection timed out"
}

func (e *TargetUnreachableError) Error() string {
	return "target is not reachable through the bastion: " + e.Reason
}

// ssh log markers. "open failed" is logged at INFO; "open confirm" needs -vv (DEBUG2),
// which SpawnDetached and SpawnDetachedWithSudo pass.
const (
	sshOpenFailedMarker  = "open failed"
	sshOpenConfirmMarker = "open confirm"
)

// CheckTunnel verifies a tunnel end to end. A listening local port only proves ssh
// started: ssh binds it before any traffic reaches the target. So after the port is
// up, CheckTunnel opens one connection through it, which makes ssh ask the bastion
// to connect to the target, and reads the ssh log to see whether that succeeded.
//
// Returns nil when the bastion confirmed the connection, ErrTunnelNotListening,
// *TargetUnreachableError, or ErrTunnelUnconfirmed.
func CheckTunnel(localPort int, logFile string, listenTimeout, probeTimeout time.Duration) error {
	if err := WaitForListen(localPort, listenTimeout); err != nil {
		return ErrTunnelNotListening
	}
	if logFile == "" {
		return ErrTunnelUnconfirmed
	}

	offset := fileSize(logFile)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 2*time.Second)
	if err != nil {
		return ErrTunnelNotListening
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(probeTimeout)
	for time.Now().Before(deadline) {
		if failed, line := scanLogFrom(logFile, offset); failed {
			return &TargetUnreachableError{Reason: line}
		} else if line != "" {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return ErrTunnelUnconfirmed
}

// scanLogFrom reads logFile from offset and reports the first channel-open outcome.
// It returns (true, line) on failure, (false, line) on confirmation, and (false, "") if neither appears yet.
func scanLogFrom(logFile string, offset int64) (bool, string) {
	data, err := os.ReadFile(logFile)
	if err != nil || int64(len(data)) <= offset {
		return false, ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data[offset:]))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.Contains(line, sshOpenFailedMarker):
			return true, line
		case strings.Contains(line, sshOpenConfirmMarker):
			return false, line
		}
	}
	return false, ""
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// RDPFileContent returns a minimal .rdp file pointing an RDP client at 127.0.0.1:localPort.
func RDPFileContent(localPort int) string {
	return fmt.Sprintf("full address:s:127.0.0.1:%d\r\nprompt for credentials:i:1\r\n", localPort)
}

// WriteRDPFile writes an .rdp file for the local end of an RDP tunnel and returns its path.
// Opening it (`open <file>` on macOS, double-click on Windows) launches the RDP client;
// this works with both Microsoft Remote Desktop and the newer Windows App.
func WriteRDPFile(localPort int) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, flags.OCIConfigDirName, flags.OCISessionsDirName, os.Getenv(flags.EnvKeyProfile), "rdp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create rdp dir: %w", err)
	}
	path := filepath.Join(dir, fmt.Sprintf("localhost-%d.rdp", localPort))
	if err := os.WriteFile(path, []byte(RDPFileContent(localPort)), 0o644); err != nil {
		return "", fmt.Errorf("write rdp file: %w", err)
	}
	return path, nil
}
