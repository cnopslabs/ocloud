package oke

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// This file is a native Go port of `oci ce cluster generate-token`
// (oci-cli: services/container_engine/src/oci_cli_container_engine/containerengine_cli_extended.py).
// It lets kubectl authenticate to OKE clusters without the OCI CLI installed.

const (
	// ExecCredentialAPIVersion is the client-go exec plugin API version OKE kubeconfigs use.
	ExecCredentialAPIVersion = "client.authentication.k8s.io/v1beta1"
	// TokenTTL mirrors the OCI CLI: tell kubectl to refresh the token after 4 minutes.
	TokenTTL = 4 * time.Minute
)

// ExecCredential is the object a Kubernetes exec credential plugin prints on stdout.
type ExecCredential struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	Status     ExecCredentialStatus `json:"status"`
}

// ExecCredentialStatus holds the bearer token and its expiry.
type ExecCredentialStatus struct {
	Token               string `json:"token"`
	ExpirationTimestamp string `json:"expirationTimestamp"`
}

// clusterRequestURL returns the URL OKE uses to validate tokens for the given cluster.
// The domain comes from the SDK's region→realm mapping, so it is also correct outside oc1.
func clusterRequestURL(region, clusterID string) string {
	host := common.StringToRegion(region).Endpoint("containerengine")
	return fmt.Sprintf("https://%s/cluster_request/%s", host, clusterID)
}

// GenerateToken builds an OKE bearer token: a GET request to the cluster_request endpoint
// is signed, its authorization and date headers are moved into the query string, and the
// resulting URL is base64url-encoded (with padding, like Python's urlsafe_b64encode).
func GenerateToken(signer common.HTTPRequestSigner, region, clusterID string, now time.Time) (string, error) {
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" {
		return "", fmt.Errorf("cluster id cannot be empty")
	}
	region = strings.TrimSpace(region)
	if region == "" {
		return "", fmt.Errorf("region cannot be empty")
	}

	req, err := http.NewRequest(http.MethodGet, clusterRequestURL(region, clusterID), nil)
	if err != nil {
		return "", fmt.Errorf("building cluster request: %w", err)
	}
	req.Header.Set("Date", now.UTC().Format(http.TimeFormat))
	if err := signer.Sign(req); err != nil {
		return "", fmt.Errorf("signing cluster request: %w", err)
	}

	q := url.Values{}
	q.Set("authorization", req.Header.Get("Authorization"))
	q.Set("date", req.Header.Get("Date"))
	tokenURL := *req.URL
	tokenURL.RawQuery = q.Encode()

	return base64.URLEncoding.EncodeToString([]byte(tokenURL.String())), nil
}

// NewExecCredential wraps a token in an ExecCredential that expires TokenTTL after now.
func NewExecCredential(token string, now time.Time) ExecCredential {
	return ExecCredential{
		APIVersion: ExecCredentialAPIVersion,
		Kind:       "ExecCredential",
		Status: ExecCredentialStatus{
			Token:               token,
			ExpirationTimestamp: now.UTC().Add(TokenTTL).Format(time.RFC3339),
		},
	}
}

// GenerateExecCredentialJSON generates a token and returns the ExecCredential as JSON.
func GenerateExecCredentialJSON(signer common.HTTPRequestSigner, region, clusterID string, now time.Time) ([]byte, error) {
	token, err := GenerateToken(signer, region, clusterID, now)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(NewExecCredential(token, now), "", "    ")
}

// SessionTokenExpiry returns the "exp" claim of an OCI session token (a JWT).
// The "ST$" key-id prefix is accepted and stripped.
func SessionTokenExpiry(token string) (time.Time, error) {
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
