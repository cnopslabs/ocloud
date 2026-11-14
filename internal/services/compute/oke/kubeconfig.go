package oke

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// kubeconfig model (unexported).
//
// Every struct carries an inline Extra map so that fields ocloud does not model
// (client certificates, auth-provider, certificate-authority paths, proxy-url,
// preferences, extensions, ...) survive a read-modify-write of ~/.kube/config.
type kubeConfig struct {
	APIVersion     string         `yaml:"apiVersion"`
	Kind           string         `yaml:"kind,omitempty"`
	Clusters       []namedCluster `yaml:"clusters"`
	Users          []namedUser    `yaml:"users"`
	Contexts       []namedContext `yaml:"contexts"`
	CurrentContext string         `yaml:"current-context"`
	Extra          map[string]any `yaml:",inline"`
}

// a namedCluster represents a named Kubernetes cluster configuration consisting of a name and its corresponding details.
type namedCluster struct {
	Name    string         `yaml:"name"`
	Cluster kcCluster      `yaml:"cluster"`
	Extra   map[string]any `yaml:",inline"`
}

// kcCluster represents a Kubernetes cluster configuration consisting of a server address and certificate details.
type kcCluster struct {
	Server                   string         `yaml:"server"`
	CertificateAuthorityData string         `yaml:"certificate-authority-data,omitempty"`
	InsecureSkipTLSVerify    bool           `yaml:"insecure-skip-tls-verify,omitempty"`
	Extra                    map[string]any `yaml:",inline"`
}

// namedUser represents a named Kubernetes user configuration consisting of a name and its corresponding details.
type namedUser struct {
	Name  string         `yaml:"name"`
	User  kcUser         `yaml:"user"`
	Extra map[string]any `yaml:",inline"`
}

// kcUser represents a Kubernetes user configuration.
type kcUser struct {
	Exec  *kcExec        `yaml:"exec,omitempty"`
	Extra map[string]any `yaml:",inline"`
}

// kcExec represents a Kubernetes exec configuration.
type kcExec struct {
	APIVersion         string         `yaml:"apiVersion"`
	Command            string         `yaml:"command"`
	Args               []string       `yaml:"args,omitempty"`
	Env                []any          `yaml:"env,omitempty"`
	InteractiveMode    string         `yaml:"interactiveMode,omitempty"`
	ProvideClusterInfo bool           `yaml:"provideClusterInfo,omitempty"`
	Extra              map[string]any `yaml:",inline"`
}

// namedContext represents a named Kubernetes context configuration consisting of a name and its corresponding details.
type namedContext struct {
	Name    string         `yaml:"name"`
	Context kcContext      `yaml:"context"`
	Extra   map[string]any `yaml:",inline"`
}

// kcContext represents Kubernetes context details including cluster, namespace, and user mappings.
type kcContext struct {
	Cluster   string         `yaml:"cluster"`
	Namespace string         `yaml:"namespace,omitempty"`
	User      string         `yaml:"user"`
	Extra     map[string]any `yaml:",inline"`
}

// KubeconfigStatus describes whether ~/.kube/config already has an entry for an OKE cluster.
type KubeconfigStatus int

const (
	// KubeconfigMissing means no user entry generates tokens for the cluster.
	KubeconfigMissing KubeconfigStatus = iota
	// KubeconfigLegacyOCI means an entry exists but calls `oci ce cluster generate-token`.
	KubeconfigLegacyOCI
	// KubeconfigCurrent means an entry exists and calls `ocloud compute oke token`.
	KubeconfigCurrent
)

const ocloudBinary = "ocloud"

// kubeconfigPath returns ~/.kube/config.
func kubeconfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(home, ".kube", "config"), nil
}

// loadKubeconfig reads the kubeconfig at path. A missing file yields an empty config;
// a file that cannot be parsed is an error, so it is never overwritten blindly.
func loadKubeconfig(path string) (kubeConfig, error) {
	var kc kubeConfig
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return kubeConfig{APIVersion: "v1", Kind: "Config"}, nil
	}
	if err != nil {
		return kc, fmt.Errorf("read kubeconfig: %w", err)
	}
	if err := yaml.Unmarshal(b, &kc); err != nil {
		return kc, fmt.Errorf("parse kubeconfig %s (left unchanged): %w", path, err)
	}
	if kc.APIVersion == "" {
		kc.APIVersion = "v1"
	}
	return kc, nil
}

// writeKubeconfig backs up the existing file to <path>.bak and atomically replaces it.
func writeKubeconfig(path string, kc kubeConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("ensure kube dir: %w", err)
	}
	if old, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".bak", old, 0o600); err != nil {
			return fmt.Errorf("back up kubeconfig: %w", err)
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-ocloud-*")
	if err != nil {
		return fmt.Errorf("create temp kubeconfig: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	enc := yaml.NewEncoder(tmp)
	enc.SetIndent(2)
	if err := enc.Encode(&kc); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("marshal kubeconfig: %w", err)
	}
	if err := enc.Close(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("finalize kubeconfig write: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod kubeconfig: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close kubeconfig: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace kubeconfig: %w", err)
	}
	return nil
}

// DefaultKubeContextName returns the context name ocloud uses for a cluster by default.
func DefaultKubeContextName(cluster Cluster) string {
	return "context-" + shortID(cluster.OCID)
}

// ocloudCommand returns the command kubectl should run for `compute oke token`. Tests replace it.
var ocloudCommand = func() string {
	self, err := os.Executable()
	if err != nil {
		return ocloudBinary
	}
	return resolveOcloudCommand(self, exec.LookPath)
}

// resolveOcloudCommand returns plain "ocloud" when that resolves on PATH to the running
// binary (stable across brew upgrades); otherwise the absolute path of the running binary,
// so a dev build is not shadowed by an older ocloud that lacks `compute oke token`.
func resolveOcloudCommand(self string, lookPath func(string) (string, error)) string {
	selfReal, err := filepath.EvalSymlinks(self)
	if err != nil {
		return ocloudBinary
	}
	if onPath, err := lookPath(ocloudBinary); err == nil {
		if real, err := filepath.EvalSymlinks(onPath); err == nil && real == selfReal {
			return ocloudBinary
		}
	}
	return self
}

// tokenCommandArgs is the ocloud subcommand path kubectl runs to get a token.
var tokenCommandArgs = []string{"compute", "oke", "token"}

// newOKEExec returns the exec entry that makes kubectl call `ocloud compute oke token`.
// Like the OCI CLI entries it replaces, it does not pin a profile: kubectl's
// OCI_CLI_PROFILE environment decides, so switching profiles keeps working.
func newOKEExec(clusterID, region string) *kcExec {
	return &kcExec{
		APIVersion:      ExecCredentialAPIVersion,
		Command:         ocloudCommand(),
		Args:            append(slices.Clone(tokenCommandArgs), "--cluster-id", clusterID, "--region", region),
		InteractiveMode: "Never",
	}
}

// KubeconfigStatusForOKE reports whether ~/.kube/config has an entry for the cluster/region,
// and whether it still uses the OCI CLI.
func KubeconfigStatusForOKE(cluster Cluster, region string) (KubeconfigStatus, error) {
	path, err := kubeconfigPath()
	if err != nil {
		return KubeconfigMissing, err
	}
	kc, err := loadKubeconfig(path)
	if err != nil {
		return KubeconfigMissing, err
	}
	status := KubeconfigMissing
	for _, u := range kc.Users {
		if !matchOKEExec(u.User.Exec, cluster.OCID, region) {
			continue
		}
		if !isLegacyOCIExec(u.User.Exec) {
			return KubeconfigCurrent, nil
		}
		status = KubeconfigLegacyOCI
	}
	return status, nil
}

// KubeconfigExistsForOKE checks whether ~/.kube/config already contains an entry
// (OCI CLI or ocloud based) for the given OKE cluster identified by cluster ID and region.
func KubeconfigExistsForOKE(cluster Cluster, region string) (bool, error) {
	st, err := KubeconfigStatusForOKE(cluster, region)
	return st != KubeconfigMissing, err
}

// EnsureKubeconfigForOKE adds cluster, user and context entries for the cluster, pointing at
// the bastion tunnel on localPort and authenticating with `ocloud compute oke token`.
// contextName may be empty to use DefaultKubeContextName. If an entry for the cluster/region
// already exists (in either form) it is a no-op; use MigrateKubeconfigForOKE to convert one.
func EnsureKubeconfigForOKE(cluster Cluster, region string, localPort int, contextName string) error {
	path, err := kubeconfigPath()
	if err != nil {
		return err
	}
	kc, err := loadKubeconfig(path)
	if err != nil {
		return err
	}

	for _, u := range kc.Users {
		if matchOKEExec(u.User.Exec, cluster.OCID, region) {
			return nil
		}
	}

	suffix := shortID(cluster.OCID)
	cName := "cluster-" + suffix
	uName := "user-" + suffix
	ctxName := strings.TrimSpace(contextName)
	if ctxName == "" {
		ctxName = DefaultKubeContextName(cluster)
	}

	kc.Clusters = upsertCluster(kc.Clusters, namedCluster{
		Name: cName,
		Cluster: kcCluster{
			Server:                fmt.Sprintf("https://127.0.0.1:%d", localPort),
			InsecureSkipTLSVerify: true,
		},
	})
	kc.Users = upsertUser(kc.Users, namedUser{
		Name: uName,
		User: kcUser{Exec: newOKEExec(cluster.OCID, region)},
	})
	kc.Contexts = upsertContext(kc.Contexts, namedContext{
		Name:    ctxName,
		Context: kcContext{Cluster: cName, User: uName},
	})
	if kc.CurrentContext == "" {
		kc.CurrentContext = ctxName
	}

	return writeKubeconfig(path, kc)
}

// MigrateKubeconfigForOKE rewrites user entries that call `oci ce cluster generate-token`
// for the cluster/region to call `ocloud compute oke token` instead. Only the exec section of those
// users changes; everything else is preserved and the previous file is kept as config.bak.
// It returns how many entries were rewritten.
func MigrateKubeconfigForOKE(cluster Cluster, region string) (int, error) {
	path, err := kubeconfigPath()
	if err != nil {
		return 0, err
	}
	kc, err := loadKubeconfig(path)
	if err != nil {
		return 0, err
	}

	n := 0
	for i := range kc.Users {
		e := kc.Users[i].User.Exec
		if !matchOKEExec(e, cluster.OCID, region) || !isLegacyOCIExec(e) {
			continue
		}
		next := newOKEExec(cluster.OCID, region)
		next.Env = e.Env // keep any env the user configured, e.g. OCI_CLI_PROFILE
		kc.Users[i].User.Exec = next
		n++
	}
	if n == 0 {
		return 0, nil
	}
	return n, writeKubeconfig(path, kc)
}

// shortID returns a shortened version of the given cluster id.
func shortID(id string) string {
	// Try to take suffix after the last '.' or '/'
	s := id
	if idx := strings.LastIndex(s, "."); idx >= 0 {
		s = s[idx+1:]
	}
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		s = s[idx+1:]
	}
	if len(s) > 12 {
		s = s[len(s)-12:]
	}
	return s
}

// upsert* functions are used to upsert an element into an array of named elements.
func upsertCluster(arr []namedCluster, item namedCluster) []namedCluster {
	for i, v := range arr {
		if v.Name == item.Name {
			arr[i] = item
			return arr
		}
	}
	return append(arr, item)
}

// upsert* functions are used to upsert an element into an array of named elements.
func upsertUser(arr []namedUser, item namedUser) []namedUser {
	for i, v := range arr {
		if v.Name == item.Name {
			arr[i] = item
			return arr
		}
	}
	return append(arr, item)
}

// upsert* functions are used to upsert an element into an array of named elements.
func upsertContext(arr []namedContext, item namedContext) []namedContext {
	for i, v := range arr {
		if v.Name == item.Name {
			arr[i] = item
			return arr
		}
	}
	return append(arr, item)
}

// isLegacyOCIExec reports whether the exec entry calls the OCI CLI.
func isLegacyOCIExec(e *kcExec) bool {
	return e != nil && filepath.Base(e.Command) == "oci"
}

// matchOKEExec returns true if the exec entry generates OKE tokens for the given cluster
// and region, either with `oci ce cluster generate-token` or `ocloud compute oke token`.
func matchOKEExec(e *kcExec, clusterID, region string) bool {
	if e == nil {
		return false
	}
	switch filepath.Base(e.Command) {
	case "oci":
		if !containsStr(e.Args, "generate-token") {
			return false
		}
	case ocloudBinary:
		if !isOcloudTokenArgs(e.Args) {
			return false
		}
	default:
		return false
	}
	flags := parseArgsToMap(e.Args)
	return flags["--cluster-id"] == clusterID && flags["--region"] == region
}

// isOcloudTokenArgs reports whether args invoke ocloud's token command:
// `compute|comp oke token ...` or the deprecated `oke-token ...`.
func isOcloudTokenArgs(args []string) bool {
	if len(args) >= 1 && args[0] == "oke-token" {
		return true
	}
	return len(args) >= 3 && (args[0] == "compute" || args[0] == "comp") && args[1] == "oke" && args[2] == "token"
}

// parseArgsToMap converts a slice of CLI args into a simple flag->value map.
// Supports both ["--flag", "value"] and ["--flag=value"] forms.
func parseArgsToMap(args []string) map[string]string {
	out := make(map[string]string)
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			if idx := strings.IndexByte(a, '='); idx > 0 {
				key := a[:idx]
				val := a[idx+1:]
				out[key] = val
				continue
			}
			// no equal sign, take next as value if present and not a flag
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				out[a] = args[i+1]
				i++
			} else {
				out[a] = ""
			}
		}
	}
	return out
}

func containsStr(arr []string, needle string) bool {
	return slices.Contains(arr, needle)
}
