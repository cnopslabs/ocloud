package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Files in ~/.oci/sessions/<profile>/ shared with the original oci_auth_refresher.sh,
// so status reporting works the same with either refresher.
const (
	PIDFileName    = "refresher.pid"
	StatusFileName = "session_status"
	LogFileName    = "refresher.log"

	StatusValid   = "valid"
	StatusExpired = "expired"

	// RefresherCommand is the hidden subcommand that runs the background loop.
	RefresherCommand = "refresher"
	// legacyScriptName identifies the bash refresher from earlier releases.
	legacyScriptName = "oci_auth_refresher.sh"
)

// SessionDir returns ~/.oci/sessions/<profile>, where the refresher keeps its files.
func SessionDir(profile string) string {
	return expandHome(filepath.Join("~", ".oci", "sessions", profile))
}

// Daemon keeps one profile's session alive by refreshing it shortly before it expires,
// like oci_auth_refresher.sh. It stops when the session can no longer be refreshed.
type Daemon struct {
	ConfigFile string
	Profile    string
	// Dir holds refresher.pid and session_status; defaults to SessionDir(Profile).
	Dir       string
	Refresher *Refresher
	// Lead is how long before expiry to refresh (default 60s, as in the script).
	Lead time.Duration
	// MaxNap caps each sleep so wall-clock jumps (laptop sleep) are noticed (default 30s).
	MaxNap time.Duration
	// RetryEvery is the wait after a failed refresh while the session is still valid (default 15s).
	RetryEvery time.Duration
	Log        io.Writer
	Now        func() time.Time
	Sleep      func(ctx context.Context, d time.Duration) error
}

func (d *Daemon) defaults() {
	if d.Dir == "" {
		d.Dir = SessionDir(d.Profile)
	}
	if d.Refresher == nil {
		d.Refresher = &Refresher{}
	}
	if d.Lead == 0 {
		d.Lead = 60 * time.Second
	}
	if d.MaxNap == 0 {
		d.MaxNap = 30 * time.Second
	}
	if d.RetryEvery == 0 {
		d.RetryEvery = 15 * time.Second
	}
	if d.Log == nil {
		d.Log = io.Discard
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Sleep == nil {
		d.Sleep = func(ctx context.Context, dur time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(dur):
				return nil
			}
		}
	}
	if d.Refresher.Now == nil {
		d.Refresher.Now = d.Now
	}
}

func (d *Daemon) logf(level, format string, args ...any) {
	_, _ = fmt.Fprintf(d.Log, "%s [%s] %s\n", d.Now().Format(time.RFC3339), level, fmt.Sprintf(format, args...))
}

func (d *Daemon) setStatus(s string) {
	_ = os.WriteFile(filepath.Join(d.Dir, StatusFileName), []byte(s+"\n"), 0o600)
}

func (d *Daemon) expired(reason string, err error) error {
	d.setStatus(StatusExpired)
	d.logf("INFO", "Session expired. Reason: %s", reason)
	return err
}

// Run loops until the session expires or cannot be refreshed (returning the reason), or
// until ctx is cancelled (returning nil). It records its PID in refresher.pid and removes
// the file on exit if it still holds that PID.
func (d *Daemon) Run(ctx context.Context) error {
	d.defaults()
	if err := os.MkdirAll(d.Dir, 0o700); err != nil {
		return err
	}
	pidFile := filepath.Join(d.Dir, PIDFileName)
	self := strconv.Itoa(os.Getpid())
	_ = os.WriteFile(pidFile, []byte(self), 0o600)
	defer func() {
		if b, err := os.ReadFile(pidFile); err == nil && strings.TrimSpace(string(b)) == self {
			_ = os.Remove(pidFile)
		}
	}()

	d.logf("INFO", "Refresher started for profile %s (pid %s)", d.Profile, self)
	var announced time.Time
	for {
		if ctx.Err() != nil {
			d.logf("INFO", "Refresher stopped")
			return nil
		}
		exp, err := ValidateLocal(d.ConfigFile, d.Profile, d.Now())
		if err != nil {
			return d.expired(err.Error(), err)
		}
		d.setStatus(StatusValid)

		if wait := exp.Sub(d.Now()) - d.Lead; wait > 0 {
			if !exp.Equal(announced) {
				d.logf("INFO", "%s; refreshing in %d seconds", ValidMessage(exp), int(wait.Seconds()))
				announced = exp
			}
			_ = d.Sleep(ctx, min(wait, d.MaxNap))
			continue
		}

		_, newExp, err := d.Refresher.RefreshIfExpiringWithin(ctx, d.ConfigFile, d.Profile, d.Lead)
		switch {
		case errors.Is(err, ErrSessionNotRefreshable):
			return d.expired("refresh rejected by OCI (maximum session lifetime reached or session revoked)", err)
		case err != nil:
			if ctx.Err() != nil {
				continue
			}
			d.logf("WARN", "Refresh failed, retrying in %s: %v", d.RetryEvery, err)
			_ = d.Sleep(ctx, d.RetryEvery)
			continue
		}
		d.logf("INFO", "Session refreshed successfully. %s", ValidMessage(newExp))
		if newExp.Sub(d.Now()) <= d.Lead {
			// OCI returned a token that is already within the refresh window; don't spin.
			_ = d.Sleep(ctx, d.RetryEvery)
		}
	}
}

// RefresherKind says which implementation a running refresher process is.
type RefresherKind string

const (
	RefresherNone   RefresherKind = ""
	RefresherGo     RefresherKind = "ocloud"
	RefresherScript RefresherKind = "script"
)

// processCommand returns a process's command line; replaced in tests.
var processCommand = func(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// classifyRefresher decides whether a command line is a refresher for profile.
func classifyRefresher(cmdline, profile string) RefresherKind {
	fields := strings.Fields(cmdline)
	switch {
	case strings.Contains(cmdline, legacyScriptName):
		for _, f := range fields {
			if f == profile {
				return RefresherScript
			}
		}
	case strings.Contains(cmdline, " session "+RefresherCommand):
		for i, f := range fields {
			if (f == "--profile" && i+1 < len(fields) && fields[i+1] == profile) || f == "--profile="+profile {
				return RefresherGo
			}
		}
	}
	return RefresherNone
}

// RunningRefresher reports the refresher recorded in the profile's refresher.pid, if that
// process is alive and really is a refresher (ocloud or the legacy script) for the profile.
// A stale PID file is removed.
func RunningRefresher(profile string) (int, RefresherKind) {
	pidFile := filepath.Join(SessionDir(profile), PIDFileName)
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, RefresherNone
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		_ = os.Remove(pidFile)
		return 0, RefresherNone
	}
	cmdline, err := processCommand(pid)
	if err != nil {
		_ = os.Remove(pidFile)
		return 0, RefresherNone
	}
	kind := classifyRefresher(cmdline, profile)
	if kind == RefresherNone {
		_ = os.Remove(pidFile)
	}
	return pid, kind
}

// StartResult describes what StartRefresher did.
type StartResult struct {
	PID            int
	AlreadyRunning bool
	ReplacedScript bool
	LogFile        string
}

// StartRefresher starts `<this binary> config session refresher` detached from the terminal,
// with output appended to refresher.log. If an ocloud refresher already runs for the
// profile it is reused; a legacy script refresher is stopped and replaced.
func StartRefresher(configFile, profile string) (StartResult, error) {
	dir := SessionDir(profile)
	res := StartResult{LogFile: filepath.Join(dir, LogFileName)}

	switch pid, kind := RunningRefresher(profile); kind {
	case RefresherGo:
		res.PID, res.AlreadyRunning = pid, true
		return res, nil
	case RefresherScript:
		stopLegacyScript(pid)
		res.ReplacedScript = true
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return res, fmt.Errorf("create session dir: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return res, fmt.Errorf("locate ocloud binary: %w", err)
	}
	logFile, err := os.OpenFile(res.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return res, fmt.Errorf("open refresher log: %w", err)
	}
	defer logFile.Close()
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return res, err
	}
	defer devNull.Close()

	cmd := exec.Command(self, "config", "session", RefresherCommand, "--profile", profile, "--config-file", configFile)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devNull, logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // survive the terminal closing
	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("start refresher: %w", err)
	}
	res.PID = cmd.Process.Pid
	// The daemon writes this too; writing it here means status is correct immediately.
	_ = os.WriteFile(filepath.Join(dir, PIDFileName), []byte(strconv.Itoa(res.PID)), 0o600)
	_ = cmd.Process.Release()
	return res, nil
}

// stopLegacyScript stops oci_auth_refresher.sh and its children (it spends most of its life
// in a long `sleep`, which would otherwise be left behind), then waits for it to exit so its
// EXIT trap (which deletes refresher.pid) cannot run after the new refresher wrote the file.
func stopLegacyScript(pid int) {
	_ = exec.Command("pkill", "-TERM", "-P", strconv.Itoa(pid)).Run()
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for range 30 {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
