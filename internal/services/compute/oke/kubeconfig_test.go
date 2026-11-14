package oke

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	kcClusterID = "ocid1.cluster.oc1.iad.aaaaaaaa5aoqs4ignyheoo2bdtwtrvgsva37rpjfmuxz3bkfmcldeglbtifa"
	kcRegion    = "us-ashburn-1"
)

// A kubeconfig with entries ocloud does not manage, using fields outside ocloud's model.
const foreignKubeconfig = `apiVersion: v1
kind: Config
preferences:
  colors: true
clusters:
- name: prod
  cluster:
    server: https://10.0.0.1:6443
    certificate-authority: /etc/prod-ca.crt
    proxy-url: socks5://localhost:1080
    tls-server-name: prod.internal
users:
- name: prod-admin
  user:
    client-certificate-data: Q0VSVA==
    client-key-data: S0VZ
- name: eks
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: aws
      args: [eks, get-token, --cluster-name, x]
      interactiveMode: IfAvailable
contexts:
- name: prod
  context:
    cluster: prod
    user: prod-admin
    namespace: payments
    extensions:
    - name: x
      extension: {a: b}
current-context: prod
`

func legacyKubeconfig(extra string) string {
	return `apiVersion: v1
kind: Config
clusters:
- name: cluster-cldeglbtifa
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
users:
- name: user-cldeglbtifa
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: oci
      args: [ce, cluster, generate-token, --cluster-id, ` + kcClusterID + `, --region, ` + kcRegion + `, --auth, security_token]
      env: []
      interactiveMode: ""
      provideClusterInfo: false
` + extra + `contexts:
- name: context-cldeglbtifa
  context:
    cluster: cluster-cldeglbtifa
    user: user-cldeglbtifa
current-context: context-cldeglbtifa
`
}

// withKubeconfig points HOME at a temp dir holding the given kubeconfig ("" = none).
func withKubeconfig(t *testing.T, content string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".kube", "config")
	if content != "" {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	return path
}

func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, yaml.Unmarshal(b, &m))
	return m
}

func findNamed(t *testing.T, m map[string]any, list, name string) map[string]any {
	t.Helper()
	for _, it := range m[list].([]any) {
		e := it.(map[string]any)
		if e["name"] == name {
			return e
		}
	}
	t.Fatalf("%s %q not found", list, name)
	return nil
}

func execOf(t *testing.T, m map[string]any, user string) map[string]any {
	t.Helper()
	return findNamed(t, m, "users", user)["user"].(map[string]any)["exec"].(map[string]any)
}

func cluster() Cluster { return Cluster{OCID: kcClusterID} }

func TestMain(m *testing.M) {
	// Under `go test` os.Executable() is the test binary; pin the plain command name.
	ocloudCommand = func() string { return "ocloud" }
	os.Exit(m.Run())
}

func TestResolveOcloudCommand(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "cellar", "ocloud")
	require.NoError(t, os.MkdirAll(filepath.Dir(self), 0o755))
	require.NoError(t, os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755))
	link := filepath.Join(dir, "bin", "ocloud")
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
	require.NoError(t, os.Symlink(self, link))

	onPath := func(p string) func(string) (string, error) {
		return func(string) (string, error) { return p, nil }
	}
	notOnPath := func(string) (string, error) { return "", os.ErrNotExist }

	assert.Equal(t, "ocloud", resolveOcloudCommand(self, onPath(link)), "PATH symlink to the same binary (brew)")
	assert.Equal(t, "ocloud", resolveOcloudCommand(link, onPath(link)))
	assert.Equal(t, self, resolveOcloudCommand(self, notOnPath), "not on PATH: absolute path")

	other := filepath.Join(dir, "old-ocloud")
	require.NoError(t, os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755))
	assert.Equal(t, self, resolveOcloudCommand(self, onPath(other)), "a different ocloud on PATH must not be used")
}

func TestEnsureKubeconfig_PreservesForeignEntries(t *testing.T) {
	path := withKubeconfig(t, foreignKubeconfig)
	before := readYAML(t, path)

	require.NoError(t, EnsureKubeconfigForOKE(cluster(), kcRegion, 6443, "c1"))

	after := readYAML(t, path)
	assert.Equal(t, before["preferences"], after["preferences"])
	assert.Equal(t, findNamed(t, before, "clusters", "prod"), findNamed(t, after, "clusters", "prod"))
	assert.Equal(t, findNamed(t, before, "users", "prod-admin"), findNamed(t, after, "users", "prod-admin"))
	assert.Equal(t, findNamed(t, before, "users", "eks"), findNamed(t, after, "users", "eks"))
	assert.Equal(t, findNamed(t, before, "contexts", "prod"), findNamed(t, after, "contexts", "prod"))
	assert.Equal(t, "prod", after["current-context"], "must not switch the current context")
}

func TestEnsureKubeconfig_WritesOcloudExec(t *testing.T) {
	path := withKubeconfig(t, "")
	require.NoError(t, EnsureKubeconfigForOKE(cluster(), kcRegion, 7443, "c1"))

	m := readYAML(t, path)
	e := execOf(t, m, "user-mcldeglbtifa")
	assert.Equal(t, "ocloud", filepath.Base(e["command"].(string)))
	assert.Equal(t, []any{"compute", "oke", "token", "--cluster-id", kcClusterID, "--region", kcRegion}, e["args"])
	assert.Equal(t, "Never", e["interactiveMode"])
	assert.Equal(t, "https://127.0.0.1:7443", findNamed(t, m, "clusters", "cluster-mcldeglbtifa")["cluster"].(map[string]any)["server"])
	assert.Equal(t, "c1", m["current-context"])

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestKubeconfigStatus(t *testing.T) {
	withKubeconfig(t, "")
	st, err := KubeconfigStatusForOKE(cluster(), kcRegion)
	require.NoError(t, err)
	assert.Equal(t, KubeconfigMissing, st)

	withKubeconfig(t, legacyKubeconfig(""))
	st, err = KubeconfigStatusForOKE(cluster(), kcRegion)
	require.NoError(t, err)
	assert.Equal(t, KubeconfigLegacyOCI, st)

	st, err = KubeconfigStatusForOKE(cluster(), "us-phoenix-1")
	require.NoError(t, err)
	assert.Equal(t, KubeconfigMissing, st, "different region is a different entry")

	withKubeconfig(t, "")
	require.NoError(t, EnsureKubeconfigForOKE(cluster(), kcRegion, 6443, ""))
	st, err = KubeconfigStatusForOKE(cluster(), kcRegion)
	require.NoError(t, err)
	assert.Equal(t, KubeconfigCurrent, st)
}

func TestEnsureKubeconfig_ExistingLegacyEntryIsNoop(t *testing.T) {
	path := withKubeconfig(t, legacyKubeconfig(""))
	before, _ := os.ReadFile(path)
	require.NoError(t, EnsureKubeconfigForOKE(cluster(), kcRegion, 6443, ""))
	after, _ := os.ReadFile(path)
	assert.Equal(t, string(before), string(after), "Ensure must not silently rewrite; migration is opt-in")
}

func TestMigrateKubeconfig_RewritesOnlyMatchingExec(t *testing.T) {
	otherCluster := `- name: user-other
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: oci
      args: [ce, cluster, generate-token, --cluster-id, ocid1.cluster.oc1.iad.other, --region, us-ashburn-1]
`
	path := withKubeconfig(t, legacyKubeconfig(otherCluster))
	before := readYAML(t, path)

	n, err := MigrateKubeconfigForOKE(cluster(), kcRegion)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	after := readYAML(t, path)
	e := execOf(t, after, "user-cldeglbtifa")
	assert.Equal(t, "ocloud", filepath.Base(e["command"].(string)))
	assert.Equal(t, []any{"compute", "oke", "token", "--cluster-id", kcClusterID, "--region", kcRegion}, e["args"])

	assert.Equal(t, findNamed(t, before, "users", "user-other"), findNamed(t, after, "users", "user-other"))
	assert.Equal(t, before["contexts"], after["contexts"])
	assert.Equal(t, before["clusters"], after["clusters"])

	bak, err := os.ReadFile(path + ".bak")
	require.NoError(t, err)
	assert.Contains(t, string(bak), "generate-token", "backup holds the pre-migration file")

	n, err = MigrateKubeconfigForOKE(cluster(), kcRegion)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "second migration is a no-op")
}

func TestEnsureKubeconfig_RefusesUnparseableFile(t *testing.T) {
	path := withKubeconfig(t, "users: [this is: not: valid yaml")
	err := EnsureKubeconfigForOKE(cluster(), kcRegion, 6443, "")
	assert.Error(t, err)
	b, _ := os.ReadFile(path)
	assert.Equal(t, "users: [this is: not: valid yaml", string(b), "must not overwrite a file it cannot parse")
}

func TestMatchOKEExec(t *testing.T) {
	legacy := &kcExec{Command: "oci", Args: []string{"ce", "cluster", "generate-token", "--cluster-id", "X", "--region", "R"}}
	current := &kcExec{Command: "/opt/homebrew/bin/ocloud", Args: []string{"compute", "oke", "token", "--cluster-id=X", "--region", "R"}}
	alias := &kcExec{Command: "ocloud", Args: []string{"comp", "oke", "token", "--cluster-id", "X", "--region", "R"}}
	deprecated := &kcExec{Command: "ocloud", Args: []string{"oke-token", "--cluster-id", "X", "--region", "R"}}
	assert.True(t, matchOKEExec(alias, "X", "R"))
	assert.True(t, matchOKEExec(deprecated, "X", "R"), "v0.2.0 hand-written entries still count as current")
	assert.False(t, isLegacyOCIExec(deprecated))
	assert.False(t, matchOKEExec(&kcExec{Command: "ocloud", Args: []string{"compute", "oke", "get", "--cluster-id", "X", "--region", "R"}}, "X", "R"))
	assert.True(t, matchOKEExec(legacy, "X", "R"))
	assert.True(t, matchOKEExec(current, "X", "R"))
	assert.True(t, isLegacyOCIExec(legacy))
	assert.False(t, isLegacyOCIExec(current))
	assert.False(t, matchOKEExec(current, "Y", "R"))
	assert.False(t, matchOKEExec(&kcExec{Command: "ocloud", Args: []string{"version", "--cluster-id", "X", "--region", "R"}}, "X", "R"))
	assert.False(t, matchOKEExec(nil, "X", "R"))
}
