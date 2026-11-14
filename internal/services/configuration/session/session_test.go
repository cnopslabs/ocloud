package session

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fakeJWT(exp time.Time) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(fmt.Appendf(nil, `{"exp":%d,"sub":"u"}`, exp.Unix())) + ".c2ln"
}

type fixture struct {
	dir, config, tokenFile string
	key                    *rsa.PrivateKey
}

// newFixture writes an OCI config like `oci session authenticate` does, plus an
// unrelated API-key profile and a comment, so we can check nothing else changes.
func newFixture(t *testing.T, token string) fixture {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyFile := filepath.Join(dir, "sessions", "P", "oci_api_key.pem")
	require.NoError(t, os.MkdirAll(filepath.Dir(keyFile), 0o700))
	require.NoError(t, os.WriteFile(keyFile,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600))
	tokenFile := filepath.Join(dir, "sessions", "P", "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(token), 0o600))

	cfg := fmt.Sprintf(`# my notes
[OTHER]
user=ocid1.user.oc1..x
fingerprint=11:22
key_file=%[1]s
tenancy=ocid1.tenancy.oc1..x
region=eu-frankfurt-1

[P]
fingerprint=aa:bb
key_file=%[1]s
tenancy=ocid1.tenancy.oc1..t
region=us-ashburn-1
security_token_file=%[2]s
`, keyFile, tokenFile)
	config := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(config, []byte(cfg), 0o600))
	return fixture{dir: dir, config: config, tokenFile: tokenFile, key: key}
}

func TestTokenExpiry(t *testing.T) {
	exp := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	got, err := TokenExpiry("ST$" + fakeJWT(exp))
	require.NoError(t, err)
	assert.Equal(t, exp, got)

	got, err = TokenExpiry(fakeJWT(exp) + "\n")
	require.NoError(t, err)
	assert.Equal(t, exp, got, "trailing newline in token file is ignored")

	_, err = TokenExpiry("not-a-jwt")
	assert.Error(t, err)
	_, err = TokenExpiry(base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".e30.x")
	assert.Error(t, err, "no exp claim")
}

func TestLoadProfile(t *testing.T) {
	f := newFixture(t, fakeJWT(time.Now().Add(time.Hour)))
	p, err := LoadProfile(f.config, "P")
	require.NoError(t, err)
	assert.Equal(t, f.tokenFile, p.TokenFile)
	assert.Equal(t, "us-ashburn-1", p.Region)

	_, err = LoadProfile(f.config, "OTHER")
	assert.ErrorContains(t, err, "security_token_file")

	_, err = LoadProfile(f.config, "MISSING")
	assert.Error(t, err)
}

func TestLoadProfile_TildeAndDefaultInheritance(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".oci", "sessions", "X"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".oci", "sessions", "X", "token"), []byte("t"), 0o600))
	cfg := filepath.Join(home, ".oci", "config")
	require.NoError(t, os.WriteFile(cfg, []byte("[DEFAULT]\nregion = us-phoenix-1\n\n[X]\nsecurity_token_file = ~/.oci/sessions/X/token\n"), 0o600))

	p, err := LoadProfile(cfg, "X")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".oci", "sessions", "X", "token"), p.TokenFile)
	assert.Equal(t, "us-phoenix-1", p.Region, "region inherited from DEFAULT like the OCI CLI")
}

func TestValidateLocal(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	f := newFixture(t, fakeJWT(exp))
	got, err := ValidateLocal(f.config, "P", time.Now())
	require.NoError(t, err)
	assert.Equal(t, exp.UTC(), got)

	f = newFixture(t, fakeJWT(time.Now().Add(-time.Minute)))
	_, err = ValidateLocal(f.config, "P", time.Now())
	assert.ErrorIs(t, err, ErrSessionExpired)
}

func TestValidMessage_MatchesOCICLIFormat(t *testing.T) {
	exp := time.Date(2026, 11, 14, 15, 4, 5, 0, time.Local)
	assert.Equal(t, "Session is valid until 2026-11-14 15:04:05", ValidMessage(exp))
	// The refresher script extracts the timestamp with this exact pattern.
	assert.Regexp(t, regexp.MustCompile(`until ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})`), ValidMessage(exp))
}

// authServer fakes POST /v1/authentication/refresh and verifies the request signature.
func authServer(t *testing.T, key *rsa.PrivateKey, status int, reply string) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/authentication/refresh", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		require.NoError(t, json.Unmarshal(body, &req))
		assert.NotEmpty(t, req["currentToken"])

		auth := r.Header.Get("Authorization")
		assert.Contains(t, auth, `keyId="ST$`+req["currentToken"]+`"`, "signed with the current session token")
		assert.Contains(t, auth, `headers="date (request-target) host content-length content-type x-content-sha256"`)
		sum := sha256.Sum256(body)
		assert.Equal(t, base64.StdEncoding.EncodeToString(sum[:]), r.Header.Get("X-Content-Sha256"))

		sig := regexp.MustCompile(`signature="([^"]+)"`).FindStringSubmatch(auth)
		require.Len(t, sig, 2)
		raw, _ := base64.StdEncoding.DecodeString(sig[1])
		signing := strings.Join([]string{
			"date: " + r.Header.Get("Date"),
			"(request-target): post /v1/authentication/refresh",
			"host: " + r.Host,
			"content-length: " + r.Header.Get("Content-Length"),
			"content-type: application/json",
			"x-content-sha256: " + r.Header.Get("X-Content-Sha256"),
		}, "\n")
		d := sha256.Sum256([]byte(signing))
		assert.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, d[:], raw), "signature must verify")

		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func refresherFor(srv *httptest.Server) *Refresher {
	return &Refresher{HTTPClient: srv.Client(), Endpoint: func(string) string { return srv.URL }}
}

func TestRefresh_Success(t *testing.T) {
	f := newFixture(t, fakeJWT(time.Now().Add(5*time.Minute)))
	newTok := fakeJWT(time.Now().Add(time.Hour).Truncate(time.Second))
	srv, calls := authServer(t, f.key, 200, `{"token":"`+newTok+`"}`)
	configBefore, _ := os.ReadFile(f.config)

	res, err := refresherFor(srv).Refresh(context.Background(), f.config, "P")
	require.NoError(t, err)
	assert.Equal(t, 1, *calls)
	assert.Equal(t, srv.URL+"/v1/authentication/refresh", res.URL)

	got, _ := os.ReadFile(f.tokenFile)
	assert.Equal(t, newTok, string(got))
	info, _ := os.Stat(f.tokenFile)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	configAfter, _ := os.ReadFile(f.config)
	assert.Equal(t, string(configBefore), string(configAfter), "refresh must never touch ~/.oci/config")
}

func TestRefresh_Unauthorized(t *testing.T) {
	old := fakeJWT(time.Now().Add(time.Minute))
	f := newFixture(t, old)
	srv, _ := authServer(t, f.key, 401, `{"code":"NotAuthenticated"}`)

	_, err := refresherFor(srv).Refresh(context.Background(), f.config, "P")
	assert.ErrorIs(t, err, ErrSessionNotRefreshable)
	got, _ := os.ReadFile(f.tokenFile)
	assert.Equal(t, old, string(got), "token file untouched on failure")
}

func TestRefresh_BadReplyKeepsToken(t *testing.T) {
	for name, reply := range map[string]string{
		"server error": "boom",
		"no token":     `{}`,
		"not a jwt":    `{"token":"garbage"}`,
	} {
		t.Run(name, func(t *testing.T) {
			old := fakeJWT(time.Now().Add(time.Minute))
			f := newFixture(t, old)
			status := 200
			if name == "server error" {
				status = 500
			}
			srv, _ := authServer(t, f.key, status, reply)
			_, err := refresherFor(srv).Refresh(context.Background(), f.config, "P")
			assert.Error(t, err)
			got, _ := os.ReadFile(f.tokenFile)
			assert.Equal(t, old, string(got))
		})
	}
}

func TestDefaultEndpoint(t *testing.T) {
	assert.Equal(t, "https://auth.us-ashburn-1.oraclecloud.com", defaultEndpoint("us-ashburn-1"))
	assert.Equal(t, "https://auth.us-ashburn-1.oraclecloud.com", defaultEndpoint("iad"))
	assert.Equal(t, "https://auth.us-langley-1.oraclegovcloud.com", defaultEndpoint("us-langley-1"))
}

func TestRefreshIfExpiringWithin_SkipsFreshToken(t *testing.T) {
	f := newFixture(t, fakeJWT(time.Now().Add(time.Hour)))
	srv, calls := authServer(t, f.key, 200, `{"token":"`+fakeJWT(time.Now().Add(2*time.Hour))+`"}`)
	did, _, err := refresherFor(srv).RefreshIfExpiringWithin(context.Background(), f.config, "P", 5*time.Minute)
	require.NoError(t, err)
	assert.False(t, did)
	assert.Equal(t, 0, *calls)
}

func TestRefreshIfExpiringWithin_RefreshesSoonToExpire(t *testing.T) {
	f := newFixture(t, fakeJWT(time.Now().Add(2*time.Minute)))
	newExp := time.Now().Add(time.Hour).Truncate(time.Second)
	srv, calls := authServer(t, f.key, 200, `{"token":"`+fakeJWT(newExp)+`"}`)
	did, exp, err := refresherFor(srv).RefreshIfExpiringWithin(context.Background(), f.config, "P", 5*time.Minute)
	require.NoError(t, err)
	assert.True(t, did)
	assert.Equal(t, newExp.UTC(), exp)
	assert.Equal(t, 1, *calls)
}

func TestRefreshIfExpiringWithin_ConcurrentCallersRefreshOnce(t *testing.T) {
	f := newFixture(t, fakeJWT(time.Now().Add(2*time.Minute)))
	srv, calls := authServer(t, f.key, 200, `{"token":"`+fakeJWT(time.Now().Add(time.Hour))+`"}`)
	r := refresherFor(srv)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := r.RefreshIfExpiringWithin(context.Background(), f.config, "P", 5*time.Minute)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, *calls, "lock + re-check means only one refresh hits the auth service")
}

func TestValidateRemote(t *testing.T) {
	for name, tc := range map[string]struct {
		status  int
		wantErr error
	}{
		"accepted": {200, nil},
		"rejected": {401, ErrSessionRejected},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, fakeJWT(time.Now().Add(time.Hour)))
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/20160918/regions", r.URL.Path)
				assert.Contains(t, r.Header.Get("Authorization"), `keyId="ST$`)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				if tc.status == 200 {
					_, _ = w.Write([]byte(`[]`))
				} else {
					_, _ = w.Write([]byte(`{"code":"NotAuthenticated","message":"no"}`))
				}
			}))
			defer srv.Close()
			_, err := ValidateRemote(context.Background(), f.config, "P", srv.URL, srv.Client())
			if tc.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.wantErr)
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	t.Setenv("OCI_CLI_PROFILE", "")
	t.Setenv("OCI_CLI_CONFIG_FILE", "")
	t.Setenv("HOME", "/home/x")
	assert.Equal(t, "DEFAULT", DefaultProfile())
	assert.Equal(t, "/home/x/.oci/config", DefaultConfigFile())
	t.Setenv("OCI_CLI_PROFILE", "DEV")
	t.Setenv("OCI_CLI_CONFIG_FILE", "~/alt")
	assert.Equal(t, "DEV", DefaultProfile())
	assert.Equal(t, "/home/x/alt", DefaultConfigFile())
}
