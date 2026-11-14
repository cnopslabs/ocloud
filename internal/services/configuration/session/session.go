// Package session validates and refreshes OCI session tokens natively, replacing
// `oci session validate` and `oci session refresh`. It reads and writes the same
// files as the OCI CLI (~/.oci/config and ~/.oci/sessions/<profile>/token), so
// sessions stay interchangeable between ocloud and the CLI.
package session

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

var (
	// ErrSessionExpired means the session token's exp claim is in the past.
	ErrSessionExpired = errors.New("Session has expired")
	// ErrSessionNotRefreshable means the auth service rejected the refresh (HTTP 401),
	// usually because the session reached its maximum lifetime.
	ErrSessionNotRefreshable = errors.New("Your session is no longer valid and cannot be refreshed. " +
		"Please use 'ocloud config session authenticate' to create a new session.")
)

// TokenExpiry returns the "exp" claim of a session token (a JWT).
// A "ST$" key-id prefix and surrounding whitespace are ignored.
func TokenExpiry(token string) (time.Time, error) {
	token = strings.TrimPrefix(strings.TrimSpace(token), "ST$")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("session token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, fmt.Errorf("decoding session token payload: %w", err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("parsing session token claims: %w", err)
	}
	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("session token has no exp claim")
	}
	return time.Unix(claims.Exp, 0).UTC(), nil
}

// ValidMessage formats expiry exactly like `oci session validate`
// ("Session is valid until 2006-01-02 15:04:05", local time). The refresher script parses it.
func ValidMessage(exp time.Time) string {
	return "Session is valid until " + exp.Local().Format("2006-01-02 15:04:05")
}

// Profile is the subset of an OCI config profile needed for session operations.
type Profile struct {
	Name      string
	TokenFile string
	Region    string
}

// LoadProfile reads a profile from an OCI config file. Like the OCI CLI, keys missing from
// the profile fall back to [DEFAULT], and a leading "~" in paths means the home directory.
func LoadProfile(configFile, profile string) (Profile, error) {
	sections, err := parseINI(configFile)
	if err != nil {
		return Profile{}, err
	}
	sec, ok := sections[profile]
	if !ok {
		return Profile{}, fmt.Errorf("profile %q not found in %s", profile, configFile)
	}
	get := func(k string) string {
		if v, ok := sec[k]; ok {
			return v
		}
		return sections["DEFAULT"][k]
	}
	tokenFile := get("security_token_file")
	if tokenFile == "" {
		return Profile{}, fmt.Errorf("profile %q has no security_token_file; it is not a session profile", profile)
	}
	return Profile{Name: profile, TokenFile: expandHome(tokenFile), Region: get("region")}, nil
}

// parseINI parses the simple INI dialect of OCI config files (sections, key=value, # or ; comments).
func parseINI(path string) (map[string]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open OCI config: %w", err)
	}
	defer f.Close()

	out := map[string]map[string]string{}
	var cur map[string]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			if out[name] == nil {
				out[name] = map[string]string{}
			}
			cur = out[name]
			continue
		}
		if cur == nil {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read OCI config: %w", err)
	}
	return out, nil
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

func readToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read security_token_file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// ValidateLocal checks the session token's expiry without calling OCI
// (`oci session validate --local`). It returns the expiry, or ErrSessionExpired.
func ValidateLocal(configFile, profile string, now time.Time) (time.Time, error) {
	p, err := LoadProfile(configFile, profile)
	if err != nil {
		return time.Time{}, err
	}
	token, err := readToken(p.TokenFile)
	if err != nil {
		return time.Time{}, err
	}
	exp, err := TokenExpiry(token)
	if err != nil {
		return time.Time{}, err
	}
	if !now.Before(exp) {
		return exp, ErrSessionExpired
	}
	return exp, nil
}

// Refresher exchanges a session token for a fresh one (`oci session refresh`).
type Refresher struct {
	// HTTPClient defaults to a client with a 30s timeout.
	HTTPClient *http.Client
	// Endpoint maps a region to the auth service base URL; defaults to https://auth.<region>.<realm-domain>.
	Endpoint func(region string) string
	// Now defaults to time.Now.
	Now func() time.Time
}

// RefreshResult describes a successful refresh.
type RefreshResult struct {
	URL     string
	Expires time.Time
}

func defaultEndpoint(region string) string {
	return "https://" + common.StringToRegion(region).Endpoint("auth")
}

// sessionKeyProvider signs with a fixed session token, so the token sent in the body
// and the one in the signature's keyId are always the same.
type sessionKeyProvider struct {
	token string
	key   *rsa.PrivateKey
}

func (p sessionKeyProvider) PrivateRSAKey() (*rsa.PrivateKey, error) { return p.key, nil }
func (p sessionKeyProvider) KeyID() (string, error)                  { return "ST$" + p.token, nil }

// Refresh refreshes the profile's session token and rewrites its token file in place
// (atomically, mode 0600). ~/.oci/config is never modified. On any failure the
// existing token file is left untouched.
func (r *Refresher) Refresh(ctx context.Context, configFile, profile string) (RefreshResult, error) {
	p, err := LoadProfile(configFile, profile)
	if err != nil {
		return RefreshResult{}, err
	}
	unlock, err := lockToken(ctx, p.TokenFile)
	if err != nil {
		return RefreshResult{}, err
	}
	defer unlock()
	return r.refreshLocked(ctx, configFile, profile, p)
}

// RefreshIfExpiringWithin refreshes the session only if it expires within window.
// Concurrent callers (the background refresher, kubectl's token calls) serialize on a
// lock and re-check the token after acquiring it, so only one of them refreshes.
// It reports whether a refresh happened and the token's current expiry.
func (r *Refresher) RefreshIfExpiringWithin(ctx context.Context, configFile, profile string, window time.Duration) (bool, time.Time, error) {
	p, err := LoadProfile(configFile, profile)
	if err != nil {
		return false, time.Time{}, err
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	expiresSoon := func() (time.Time, bool, error) {
		token, err := readToken(p.TokenFile)
		if err != nil {
			return time.Time{}, false, err
		}
		exp, err := TokenExpiry(token)
		if err != nil {
			return time.Time{}, false, err
		}
		return exp, exp.Sub(now()) <= window, nil
	}

	exp, soon, err := expiresSoon()
	if err != nil || !soon {
		return false, exp, err
	}
	unlock, err := lockToken(ctx, p.TokenFile)
	if err != nil {
		return false, exp, err
	}
	defer unlock()
	if exp, soon, err = expiresSoon(); err != nil || !soon {
		return false, exp, err // another process refreshed while we waited
	}
	res, err := r.refreshLocked(ctx, configFile, profile, p)
	if err != nil {
		return false, exp, err
	}
	return true, res.Expires, nil
}

// lockToken takes an exclusive advisory lock on <token>.lock, waiting until ctx is done.
func lockToken(ctx context.Context, tokenFile string) (func(), error) {
	f, err := os.OpenFile(tokenFile+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open session lock: %w", err)
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("lock session: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("waiting for session lock: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (r *Refresher) refreshLocked(ctx context.Context, configFile, profile string, p Profile) (RefreshResult, error) {
	if p.Region == "" {
		return RefreshResult{}, fmt.Errorf("profile %q has no region", profile)
	}
	token, err := readToken(p.TokenFile)
	if err != nil {
		return RefreshResult{}, err
	}
	// The SDK resolves key_file (and pass_phrase) from the profile for us.
	provider, err := common.ConfigurationProviderForSessionTokenWithProfile(configFile, profile, "")
	if err != nil {
		return RefreshResult{}, fmt.Errorf("load session profile %q: %w", profile, err)
	}
	key, err := provider.PrivateRSAKey()
	if err != nil {
		return RefreshResult{}, fmt.Errorf("load session private key: %w", err)
	}

	endpoint := defaultEndpoint
	if r.Endpoint != nil {
		endpoint = r.Endpoint
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	url := strings.TrimRight(endpoint(p.Region), "/") + "/v1/authentication/refresh"
	body, err := json.Marshal(map[string]string{"currentToken": token})
	if err != nil {
		return RefreshResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return RefreshResult{}, fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("Date", now().UTC().Format(http.TimeFormat))
	if err := common.DefaultRequestSigner(sessionKeyProvider{token: token, key: key}).Sign(req); err != nil {
		return RefreshResult{}, fmt.Errorf("sign refresh request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return RefreshResult{URL: url}, fmt.Errorf("refresh request to %s: %w", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return RefreshResult{URL: url}, ErrSessionNotRefreshable
	case resp.StatusCode != http.StatusOK:
		return RefreshResult{URL: url}, fmt.Errorf("failed to refresh session (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return RefreshResult{URL: url}, fmt.Errorf("parse refresh response: %w", err)
	}
	exp, err := TokenExpiry(out.Token)
	if err != nil {
		return RefreshResult{URL: url}, fmt.Errorf("refresh response has no usable token (left the old one in place): %w", err)
	}
	if err := writeFileAtomic(p.TokenFile, []byte(out.Token), 0o600); err != nil {
		return RefreshResult{URL: url}, fmt.Errorf("write refreshed token: %w", err)
	}
	return RefreshResult{URL: url, Expires: exp}, nil
}

// writeFileAtomic replaces path via a temp file in the same directory and a rename,
// so readers (the SDK, kubectl's exec plugin) never see a partially written token.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".token-ocloud-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ErrSessionRejected means the OCI API returned 401 for the session (`oci session validate` without --local).
var ErrSessionRejected = errors.New("Session was deemed invalid by service")

// DefaultProfile returns $OCI_CLI_PROFILE, or DEFAULT.
func DefaultProfile() string {
	if p := os.Getenv("OCI_CLI_PROFILE"); p != "" {
		return p
	}
	return "DEFAULT"
}

// DefaultConfigFile returns $OCI_CLI_CONFIG_FILE, or ~/.oci/config.
func DefaultConfigFile() string {
	if f := os.Getenv("OCI_CLI_CONFIG_FILE"); f != "" {
		return expandHome(f)
	}
	return expandHome("~/.oci/config")
}

// ValidateRemote checks the session against OCI by listing regions, then returns its expiry.
// host overrides the identity endpoint (tests); empty means the profile's region.
func ValidateRemote(ctx context.Context, configFile, profile, host string, dispatcher common.HTTPRequestDispatcher) (time.Time, error) {
	exp, err := ValidateLocal(configFile, profile, time.Now())
	if err != nil {
		return exp, err
	}
	provider, err := common.ConfigurationProviderForSessionTokenWithProfile(configFile, profile, "")
	if err != nil {
		return exp, fmt.Errorf("load session profile %q: %w", profile, err)
	}
	client, err := identity.NewIdentityClientWithConfigurationProvider(provider)
	if err != nil {
		return exp, fmt.Errorf("create identity client: %w", err)
	}
	if host != "" {
		client.Host = host
	}
	if dispatcher != nil {
		client.HTTPClient = dispatcher
	}
	if _, err := client.ListRegions(ctx); err != nil {
		var se common.ServiceError
		if errors.As(err, &se) && se.GetHTTPStatusCode() == http.StatusUnauthorized {
			return exp, ErrSessionRejected
		}
		return exp, fmt.Errorf("validate session with OCI: %w", err)
	}
	return exp, nil
}
