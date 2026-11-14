package oke

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testClusterID = "ocid1.cluster.oc1.iad.aaaaaaaatestcluster"

func testSigner(t *testing.T) (common.HTTPRequestSigner, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider(
		"ocid1.tenancy.oc1..tenancy", "ocid1.user.oc1..user", "us-ashburn-1", "aa:bb", string(keyPEM), nil)
	return common.DefaultRequestSigner(provider), key
}

// decodeToken reverses GenerateToken and returns the presigned URL.
func decodeToken(t *testing.T, token string) *url.URL {
	t.Helper()
	raw, err := base64.URLEncoding.DecodeString(token)
	require.NoError(t, err, "token must be padded base64url like Python's urlsafe_b64encode")
	u, err := url.Parse(string(raw))
	require.NoError(t, err)
	return u
}

func TestGenerateToken_URLShape(t *testing.T) {
	signer, _ := testSigner(t)
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

	token, err := GenerateToken(signer, "us-ashburn-1", testClusterID, now)
	require.NoError(t, err)

	u := decodeToken(t, token)
	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "containerengine.us-ashburn-1.oraclecloud.com", u.Host)
	assert.Equal(t, "/cluster_request/"+testClusterID, u.Path)

	q := u.Query()
	assert.Equal(t, "Sat, 14 Nov 2026 10:00:00 GMT", q.Get("date"))
	assert.Contains(t, q.Get("authorization"), `Signature version="1"`)
	assert.Contains(t, q.Get("authorization"), `headers="date (request-target) host"`)
	assert.Contains(t, q.Get("authorization"), `keyId="ocid1.tenancy.oc1..tenancy/ocid1.user.oc1..user/aa:bb"`)
	// Same parameter order as requests.Request(params={"authorization":..., "date":...}).
	assert.True(t, strings.HasPrefix(u.RawQuery, "authorization="))
}

func TestGenerateToken_SignatureVerifies(t *testing.T) {
	signer, key := testSigner(t)
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

	token, err := GenerateToken(signer, "us-ashburn-1", testClusterID, now)
	require.NoError(t, err)
	u := decodeToken(t, token)

	sigMatch := regexp.MustCompile(`signature="([^"]+)"`).FindStringSubmatch(u.Query().Get("authorization"))
	require.Len(t, sigMatch, 2)
	sig, err := base64.StdEncoding.DecodeString(sigMatch[1])
	require.NoError(t, err)

	// This is the string OKE reconstructs from the presigned URL before verifying.
	signingString := strings.Join([]string{
		"date: " + u.Query().Get("date"),
		"(request-target): get " + u.Path,
		"host: " + u.Host,
	}, "\n")
	digest := sha256.Sum256([]byte(signingString))
	assert.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig))
}

func TestGenerateToken_RegionShortCodeAndRealm(t *testing.T) {
	signer, _ := testSigner(t)
	now := time.Now()

	token, err := GenerateToken(signer, "iad", testClusterID, now)
	require.NoError(t, err)
	assert.Equal(t, "containerengine.us-ashburn-1.oraclecloud.com", decodeToken(t, token).Host)

	token, err = GenerateToken(signer, "us-langley-1", testClusterID, now)
	require.NoError(t, err)
	assert.Equal(t, "containerengine.us-langley-1.oraclegovcloud.com", decodeToken(t, token).Host)
}

func TestGenerateToken_Validation(t *testing.T) {
	signer, _ := testSigner(t)
	_, err := GenerateToken(signer, "us-ashburn-1", "  ", time.Now())
	assert.Error(t, err)
	_, err = GenerateToken(signer, "", testClusterID, time.Now())
	assert.Error(t, err)
}

type failingSigner struct{}

func (failingSigner) Sign(*http.Request) error { return assert.AnError }

func TestGenerateToken_SignerError(t *testing.T) {
	_, err := GenerateToken(failingSigner{}, "us-ashburn-1", testClusterID, time.Now())
	assert.ErrorIs(t, err, assert.AnError)
}

func TestGenerateExecCredentialJSON(t *testing.T) {
	signer, _ := testSigner(t)
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

	out, err := GenerateExecCredentialJSON(signer, "us-ashburn-1", testClusterID, now)
	require.NoError(t, err)

	var cred ExecCredential
	require.NoError(t, json.Unmarshal(out, &cred))
	assert.Equal(t, "client.authentication.k8s.io/v1beta1", cred.APIVersion)
	assert.Equal(t, "ExecCredential", cred.Kind)
	assert.Equal(t, "2026-11-14T10:04:00Z", cred.Status.ExpirationTimestamp)
	assert.NotEmpty(t, cred.Status.Token)
}
