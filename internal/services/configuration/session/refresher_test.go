package session

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock drives the daemon without real sleeping: Sleep advances the clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return nil
}

type reply struct {
	status int
	body   string
}

// seqServer answers refresh requests with the given replies in order (the last one repeats)
// and records the fake-clock time of each call. Signing is covered by session_test.go.
func seqServer(t *testing.T, clock *fakeClock, replies ...reply) (*httptest.Server, *[]time.Time) {
	t.Helper()
	var mu sync.Mutex
	var at []time.Time
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		i := min(len(at), len(replies)-1)
		at = append(at, clock.Now())
		mu.Unlock()
		assert.Equal(t, "/v1/authentication/refresh", r.URL.Path)
		w.WriteHeader(replies[i].status)
		_, _ = w.Write([]byte(replies[i].body))
	}))
	t.Cleanup(srv.Close)
	return srv, &at
}

func tokenReply(exp time.Time) reply { return reply{200, `{"token":"` + fakeJWT(exp) + `"}`} }

func newDaemon(f fixture, srv *httptest.Server, clock *fakeClock, log *bytes.Buffer) *Daemon {
	return &Daemon{
		ConfigFile: f.config, Profile: "P", Dir: filepath.Join(f.dir, "state"),
		Refresher: &Refresher{HTTPClient: srv.Client(), Endpoint: func(string) string { return srv.URL }},
		Log:       log, Now: clock.Now, Sleep: clock.Sleep,
	}
}

func readStatus(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, StatusFileName))
	require.NoError(t, err)
	return strings.TrimSpace(string(b))
}

func TestDaemon_RefreshesInTimeUntilRejected(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	clock := &fakeClock{now: start}
	firstExp := start.Add(10 * time.Minute)
	secondExp := start.Add(70 * time.Minute)
	f := newFixture(t, fakeJWT(firstExp))
	// Refresh once, then OCI refuses (maximum session lifetime reached): the daemon must stop.
	srv, calls := seqServer(t, clock, tokenReply(secondExp), reply{401, `{"code":"NotAuthenticated"}`})

	var log bytes.Buffer
	d := newDaemon(f, srv, clock, &log)
	err := d.Run(context.Background())

	assert.ErrorIs(t, err, ErrSessionNotRefreshable)
	require.Len(t, *calls, 2)
	for i, exp := range []time.Time{firstExp, secondExp} {
		left := exp.Sub((*calls)[i])
		assert.True(t, left > 0 && left <= 60*time.Second, "refresh %d happened %s before expiry; want within the 60s lead", i, left)
	}
	assert.Equal(t, StatusExpired, readStatus(t, d.Dir))
	assert.Contains(t, log.String(), "Session refreshed successfully")
	assert.Contains(t, log.String(), "refresh rejected by OCI")
	_, err = os.Stat(filepath.Join(d.Dir, PIDFileName))
	assert.True(t, os.IsNotExist(err), "pid file removed on exit")
}

func TestDaemon_NapsAreBoundedAndCancelIsClean(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	clock := &fakeClock{now: start}
	f := newFixture(t, fakeJWT(start.Add(2*time.Hour)))
	srv, calls := seqServer(t, clock, tokenReply(start.Add(3*time.Hour)))

	var log bytes.Buffer
	d := newDaemon(f, srv, clock, &log)
	ctx, cancel := context.WithCancel(context.Background())
	naps := 0
	d.Sleep = func(c context.Context, dur time.Duration) error {
		naps++
		assert.LessOrEqual(t, dur, 30*time.Second, "never sleeps longer than MaxNap")
		if naps == 20 {
			cancel()
		}
		return clock.Sleep(c, dur)
	}

	require.NoError(t, d.Run(ctx), "cancellation is a clean stop")
	assert.Empty(t, *calls, "no refresh while the session has plenty of time")
	assert.Equal(t, StatusValid, readStatus(t, d.Dir))
	assert.Equal(t, 1, strings.Count(log.String(), "refreshing in"), "the wait is logged once per token, not every nap")
}

func TestDaemon_WallClockJumpIsNoticed(t *testing.T) {
	// A laptop sleeping for an hour: the next nap ends with the clock far ahead.
	start := time.Now().Truncate(time.Second)
	clock := &fakeClock{now: start}
	exp := start.Add(20 * time.Minute)
	f := newFixture(t, fakeJWT(exp))
	srv, calls := seqServer(t, clock, tokenReply(start.Add(2*time.Hour)))

	d := newDaemon(f, srv, clock, &bytes.Buffer{})
	ctx, cancel := context.WithCancel(context.Background())
	jumped := false
	d.Sleep = func(c context.Context, dur time.Duration) error {
		if !jumped {
			jumped = true
			clock.mu.Lock()
			clock.now = exp.Add(-30 * time.Second) // woke up 30s before expiry
			clock.mu.Unlock()
			return nil
		}
		if len(*calls) == 1 {
			cancel()
		}
		return clock.Sleep(c, dur)
	}
	require.NoError(t, d.Run(ctx))
	require.Len(t, *calls, 1, "refreshed right after waking instead of sleeping on")
	assert.Equal(t, exp.Add(-30*time.Second), (*calls)[0])
}

func TestDaemon_TransientFailureIsRetried(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	clock := &fakeClock{now: start}
	f := newFixture(t, fakeJWT(start.Add(5*time.Minute)))
	srv, calls := seqServer(t, clock, reply{503, "busy"}, reply{503, "busy"}, tokenReply(start.Add(time.Hour)))

	var log bytes.Buffer
	d := newDaemon(f, srv, clock, &log)
	ctx, cancel := context.WithCancel(context.Background())
	d.Sleep = func(c context.Context, dur time.Duration) error {
		if len(*calls) == 3 {
			cancel()
		}
		return clock.Sleep(c, dur)
	}

	require.NoError(t, d.Run(ctx))
	assert.Len(t, *calls, 3)
	assert.Equal(t, 2, strings.Count(log.String(), "Refresh failed, retrying"))
	assert.Equal(t, 1, strings.Count(log.String(), "Session refreshed successfully"))
	tok, _ := os.ReadFile(f.tokenFile)
	got, _ := TokenExpiry(string(tok))
	assert.Equal(t, start.Add(time.Hour).UTC(), got)
}

func TestDaemon_ExpiredAtStart(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	f := newFixture(t, fakeJWT(time.Now().Add(-time.Minute)))
	srv, calls := seqServer(t, clock, tokenReply(time.Now().Add(time.Hour)))
	d := newDaemon(f, srv, clock, &bytes.Buffer{})
	assert.ErrorIs(t, d.Run(context.Background()), ErrSessionExpired)
	assert.Empty(t, *calls, "an expired session is never sent to OCI")
	assert.Equal(t, StatusExpired, readStatus(t, d.Dir))
}

func TestClassifyRefresher(t *testing.T) {
	cases := map[string]struct {
		cmd  string
		want RefresherKind
	}{
		"go":                  {"/opt/homebrew/bin/ocloud config session refresher --profile DEV --config-file /x", RefresherGo},
		"go equals form":      {"ocloud config session refresher --profile=DEV", RefresherGo},
		"go other profile":    {"ocloud config session refresher --profile PROD", RefresherNone},
		"script via bash -c":  {"bash -c NOHUP=1 /u/.oci/.ocloud/scripts/oci_auth_refresher.sh DEV", RefresherScript},
		"script direct":       {"/bin/bash /u/.oci/.ocloud/scripts/oci_auth_refresher.sh DEV", RefresherScript},
		"script other prof":   {"/bin/bash /u/oci_auth_refresher.sh DEVX", RefresherNone},
		"unrelated pid reuse": {"/usr/bin/vim notes.txt", RefresherNone},
		"validate not daemon": {"ocloud config session validate --profile DEV", RefresherNone},
	}
	for name, c := range cases {
		assert.Equal(t, c.want, classifyRefresher(c.cmd, "DEV"), name)
	}
}

func TestRunningRefresher(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := SessionDir("DEV")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	pidFile := filepath.Join(dir, PIDFileName)

	orig := processCommand
	t.Cleanup(func() { processCommand = orig })
	cmds := map[int]string{42: "ocloud config session refresher --profile DEV", 43: "/usr/bin/vim"}
	processCommand = func(pid int) (string, error) {
		if c, ok := cmds[pid]; ok {
			return c, nil
		}
		return "", errors.New("no such process")
	}

	require.NoError(t, os.WriteFile(pidFile, []byte("42"), 0o600))
	pid, kind := RunningRefresher("DEV")
	assert.Equal(t, 42, pid)
	assert.Equal(t, RefresherGo, kind)

	for _, stale := range []int{43, 99} {
		require.NoError(t, os.WriteFile(pidFile, []byte(strconv.Itoa(stale)), 0o600))
		_, kind = RunningRefresher("DEV")
		assert.Equal(t, RefresherNone, kind)
		_, err := os.Stat(pidFile)
		assert.True(t, os.IsNotExist(err), "stale pid file %d removed", stale)
	}
}
