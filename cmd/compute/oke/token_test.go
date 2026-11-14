package oke

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cnopslabs/ocloud/internal/services/compute/oke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tokenTestClusterID = "ocid1.cluster.oc1.phx.aaaaaaaatest"

// writeConfig writes an OCI config with a session-token profile and an api-key profile.
func writeConfig(t *testing.T) string {
	return writeConfigWithToken(t, "session-token-value")
}

func writeConfigWithToken(t *testing.T, sessionToken string) string {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyFile := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyFile,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600))
	tokenFile := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(sessionToken), 0o600))

	cfg := fmt.Sprintf(`[SESSION]
fingerprint=aa:bb
key_file=%[1]s
tenancy=ocid1.tenancy.oc1..t
region=us-phoenix-1
security_token_file=%[2]s

[APIKEY]
user=ocid1.user.oc1..u
fingerprint=aa:bb
key_file=%[1]s
tenancy=ocid1.tenancy.oc1..t
region=us-phoenix-1
`, keyFile, tokenFile)
	cfgFile := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(cfgFile, []byte(cfg), 0o600))
	return cfgFile
}

func runToken(t *testing.T, args ...string) (oke.ExecCredential, string, error) {
	t.Helper()
	cmd := NewTokenCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	err := cmd.Execute()
	var cred oke.ExecCredential
	if err == nil {
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &cred), "stdout must be pure ExecCredential JSON")
	}
	return cred, decodedURL(t, cred.Status.Token), err
}

func decodedURL(t *testing.T, token string) string {
	if token == "" {
		return ""
	}
	raw, err := base64.URLEncoding.DecodeString(token)
	require.NoError(t, err)
	return string(raw)
}

func TestOKEToken_SessionTokenProfile(t *testing.T) {
	cfg := writeConfig(t)
	cred, u, err := runToken(t, "--config-file", cfg, "--profile", "SESSION", "--cluster-id", tokenTestClusterID)
	require.NoError(t, err)
	assert.Equal(t, "ExecCredential", cred.Kind)
	assert.True(t, strings.HasPrefix(u, "https://containerengine.us-phoenix-1.oraclecloud.com/cluster_request/"+tokenTestClusterID+"?"),
		"region should default to the profile's region: %s", u)
	assert.Contains(t, u, "keyId%3D%22ST%24session-token-value%22", "session token must be used as keyId")
}

func TestOKEToken_RegionFlagOverridesProfile(t *testing.T) {
	cfg := writeConfig(t)
	_, u, err := runToken(t, "--config-file", cfg, "--profile", "SESSION", "--cluster-id", tokenTestClusterID, "--region", "eu-frankfurt-1")
	require.NoError(t, err)
	assert.Contains(t, u, "https://containerengine.eu-frankfurt-1.oraclecloud.com/")
}

func TestOKEToken_APIKeyProfile(t *testing.T) {
	cfg := writeConfig(t)
	_, u, err := runToken(t, "--config-file", cfg, "--profile", "APIKEY", "--auth", "api_key", "--cluster-id", tokenTestClusterID)
	require.NoError(t, err)
	assert.Contains(t, u, "keyId%3D%22ocid1.tenancy.oc1..t%2Focid1.user.oc1..u%2Faa%3Abb%22")
}

func TestOKEToken_ProfileFromEnv(t *testing.T) {
	cfg := writeConfig(t)
	t.Setenv("OCI_CLI_PROFILE", "SESSION")
	t.Setenv(envConfigFile, cfg)
	_, u, err := runToken(t, "--cluster-id", tokenTestClusterID)
	require.NoError(t, err)
	assert.Contains(t, u, "ST%24session-token-value")
}

func TestOKEToken_Errors(t *testing.T) {
	cfg := writeConfig(t)
	_, _, err := runToken(t, "--config-file", cfg, "--profile", "SESSION")
	assert.Error(t, err, "cluster-id is required")

	_, _, err = runToken(t, "--config-file", cfg, "--profile", "SESSION", "--cluster-id", tokenTestClusterID, "--auth", "bogus")
	assert.ErrorContains(t, err, "unsupported --auth")

	_, _, err = runToken(t, "--config-file", cfg, "--profile", "APIKEY", "--cluster-id", tokenTestClusterID)
	assert.Error(t, err, "api-key profile has no security_token_file")
}

func jwtWithExp(exp time.Time) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix()))) + ".sig"
}

func TestOKEToken_ExpiredSessionFailsFast(t *testing.T) {
	cfg := writeConfigWithToken(t, jwtWithExp(time.Now().Add(-time.Minute)))
	_, _, err := runToken(t, "--config-file", cfg, "--profile", "SESSION", "--cluster-id", tokenTestClusterID)
	assert.ErrorContains(t, err, "expired")
	assert.ErrorContains(t, err, "ocloud config session authenticate")
}

func TestOKEToken_ValidSession(t *testing.T) {
	cfg := writeConfigWithToken(t, jwtWithExp(time.Now().Add(time.Hour)))
	cred, _, err := runToken(t, "--config-file", cfg, "--profile", "SESSION", "--cluster-id", tokenTestClusterID)
	require.NoError(t, err)
	assert.NotEmpty(t, cred.Status.Token)
}

func TestLegacyOKETokenAlias(t *testing.T) {
	cfg := writeConfig(t)
	cmd := NewLegacyTokenCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--config-file", cfg, "--profile", "SESSION", "--cluster-id", tokenTestClusterID})
	require.NoError(t, cmd.Execute())

	var cred oke.ExecCredential
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &cred), "deprecation notice must not pollute stdout")
	assert.NotEmpty(t, cred.Status.Token)
	assert.Contains(t, stderr.String(), "ocloud compute oke token")
	assert.True(t, cmd.Hidden)
}
