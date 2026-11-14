package bastion

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestScanLogFrom(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "t.log")
	old := "debug1: channel 1: open failed: connect failed: old failure\n"
	if err := os.WriteFile(log, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	offset := int64(len(old))

	if failed, line := scanLogFrom(log, offset); failed || line != "" {
		t.Fatalf("content before offset must be ignored, got failed=%v line=%q", failed, line)
	}

	appendLine(t, log, "debug2: channel 2: open confirm rwindow 2097152 rmax 32768")
	if failed, line := scanLogFrom(log, offset); failed || !strings.Contains(line, "open confirm") {
		t.Fatalf("want confirm, got failed=%v line=%q", failed, line)
	}

	if failed, line := scanLogFrom(filepath.Join(dir, "missing.log"), 0); failed || line != "" {
		t.Fatalf("missing log should report nothing, got failed=%v line=%q", failed, line)
	}

	log2 := filepath.Join(dir, "t2.log")
	appendLine(t, log2, "channel 2: open failed: connect failed: Connection refused")
	if failed, line := scanLogFrom(log2, 0); !failed || !strings.Contains(line, "Connection refused") {
		t.Fatalf("want failure, got failed=%v line=%q", failed, line)
	}
}

func TestRDPFile(t *testing.T) {
	if got, want := RDPFileContent(13389), "full address:s:127.0.0.1:13389\r\nprompt for credentials:i:1\r\n"; got != want {
		t.Fatalf("RDPFileContent = %q, want %q", got, want)
	}

	t.Setenv("HOME", t.TempDir())
	t.Setenv("OCI_CLI_PROFILE", "TESTPROF")
	path, err := WriteRDPFile(13389)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(path, filepath.Join("TESTPROF", "rdp", "localhost-13389.rdp")) {
		t.Fatalf("unexpected path %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != RDPFileContent(13389) {
		t.Fatalf("file content %q, err %v", data, err)
	}
}

func TestCheckTunnelNotListening(t *testing.T) {
	port := freePort(t)
	if err := CheckTunnel(port, "", 300*time.Millisecond, time.Second); !errors.Is(err, ErrTunnelNotListening) {
		t.Fatalf("want ErrTunnelNotListening, got %v", err)
	}
}

// TestCheckTunnelWithRealSSH drives the real ssh client (as spawned by SpawnDetached)
// through an in-process SSH server standing in for the OCI bastion.
func TestCheckTunnelWithRealSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	if testing.Short() {
		t.Skip("spawns ssh; skipped in -short mode")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("OCI_CLI_PROFILE", "TEST")

	keyPath := writeClientKey(t)

	// A target that accepts connections, like an RDP server listening on 3389.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()

	cases := []struct {
		name       string
		targetPort int
		hang       bool // bastion never answers the channel request (dropped packets)
		check      func(error) bool
	}{
		{"reachable target", target.Addr().(*net.TCPAddr).Port, false, func(err error) bool { return err == nil }},
		{"closed target port", freePort(t), false, func(err error) bool {
			var u *TargetUnreachableError
			return errors.As(err, &u) && strings.Contains(u.Reason, "open failed")
		}},
		{"bastion never answers", target.Addr().(*net.TCPAddr).Port, true, func(err error) bool { return errors.Is(err, ErrTunnelUnconfirmed) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bastionPort := startFakeBastion(t, tc.hang)
			localPort := freePort(t)
			args := []string{
				"-F", "/dev/null",
				"-i", keyPath,
				"-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null",
				"-o", "BatchMode=yes",
				"-N",
				"-L", fmt.Sprintf("%d:127.0.0.1:%d", localPort, tc.targetPort),
				"-p", fmt.Sprint(bastionPort),
				"session@127.0.0.1",
			}
			pid, logFile, err := SpawnDetached(args, localPort, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGTERM) })

			err = CheckTunnel(localPort, logFile, 10*time.Second, 3*time.Second)
			if !tc.check(err) {
				log, _ := os.ReadFile(logFile)
				t.Fatalf("unexpected result %v\n--- ssh log ---\n%s", err, log)
			}
		})
	}
}

// startFakeBastion runs a minimal SSH server that accepts any public key and serves
// direct-tcpip (ssh -L) requests by dialing the target, like OCI Bastion does.
func startFakeBastion(t *testing.T, hang bool) int {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serveBastionConn(nc, cfg, hang)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveBastionConn(nc net.Conn, cfg *ssh.ServerConfig, hang bool) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "direct-tcpip" {
			_ = nch.Reject(ssh.UnknownChannelType, "only direct-tcpip")
			continue
		}
		if hang {
			continue // never accept or reject, like a SYN to a firewalled port
		}
		host, port := parseDirectTCPIP(nch.ExtraData())
		target, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 2*time.Second)
		if err != nil {
			_ = nch.Reject(ssh.ConnectionFailed, "connect failed: "+err.Error())
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			_ = target.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)
		go func() { _, _ = io.Copy(ch, target); _ = ch.Close() }()
		go func() { _, _ = io.Copy(target, ch); _ = target.Close() }()
	}
}

// parseDirectTCPIP decodes the RFC 4254 direct-tcpip payload: string host, uint32 port, ...
func parseDirectTCPIP(b []byte) (string, uint32) {
	if len(b) < 4 {
		return "", 0
	}
	n := binary.BigEndian.Uint32(b)
	if len(b) < int(4+n+4) {
		return "", 0
	}
	return string(b[4 : 4+n]), binary.BigEndian.Uint32(b[4+n:])
}

func writeClientKey(t *testing.T) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}
