// Package kubeconfigtarget inspects explicit local target identity only. It
// never builds a Kubernetes client, merges defaults, runs auth plugins, returns
// user credentials or writes a kubeconfig/current-context.
package kubeconfigtarget

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

type Target struct {
	Context       string `json:"context"`
	Cluster       string `json:"cluster"`
	Endpoint      string `json:"endpoint"`
	CATrustDigest string `json:"caTrustDigest"`
}

// Authentication fields deliberately have no representation in this reader.
type configuration struct {
	APIVersion     string `yaml:"apiVersion"`
	Kind           string `yaml:"kind"`
	CurrentContext string `yaml:"current-context"`
	Contexts       []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Clusters []struct {
		Name    string           `yaml:"name"`
		Cluster clusterTransport `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
	} `yaml:"users"`
}

type clusterTransport struct {
	Server                   string `yaml:"server"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	CertificateAuthority     string `yaml:"certificate-authority"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
	ProxyURL                 string `yaml:"proxy-url"`
	TLSServerName            string `yaml:"tls-server-name"`
}

// Read selects the sole context or requires an explicitly named context when
// multiple exist. current-context is deliberately not an implicit selection.
func Read(path, context string) (Target, error) { return read(path, context, false) }

// ReadCurrent inspects the effective identity of an existing provider-access
// credential whose owner explicitly defines current-context selection. It is
// not used for selection of friendly YAML target references.
func ReadCurrent(path string) (Target, error) { return read(path, "", true) }

func read(path, selected string, current bool) (Target, error) {
	var target Target
	raw, err := readFile(path, true)
	if err != nil {
		return target, err
	}
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&document) != nil {
		return target, errors.New("invalid kubeconfig YAML")
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF || inspect(&document) != nil {
		return target, errors.New("kubeconfig requires one document, unique keys/names and no aliases")
	}
	var config configuration
	if document.Decode(&config) != nil || config.APIVersion != "v1" || config.Kind != "Config" {
		return target, errors.New("cannot parse kubeconfig target references")
	}
	if current {
		selected = config.CurrentContext
		if selected == "" {
			return target, errors.New("provider-access current-context is missing")
		}
	}
	if selected == "" {
		if len(config.Contexts) != 1 {
			return target, errors.New("kubeconfig has multiple or no contexts; specify context explicitly in cluster YAML")
		}
		selected = config.Contexts[0].Name
	}
	for _, entry := range config.Contexts {
		if entry.Name != selected {
			continue
		}
		context := entry.Context
		foundUser := false
		for _, user := range config.Users {
			if user.Name == context.User {
				foundUser = true
			}
		}
		if context.Cluster == "" || context.User == "" || !foundUser {
			return target, errors.New("selected context user/cluster references are missing")
		}
		for _, cluster := range config.Clusters {
			if cluster.Name == context.Cluster {
				return clusterTarget(path, selected, context.Cluster, cluster.Cluster)
			}
		}
		return target, errors.New("selected kubeconfig cluster is missing")
	}
	return target, errors.New("explicit kubeconfig context does not exist")
}

func clusterTarget(path, context, name string, cluster clusterTransport) (Target, error) {
	var target Target
	endpoint, err := normalizeEndpoint(cluster.Server)
	if err != nil || cluster.InsecureSkipTLSVerify || cluster.ProxyURL != "" || cluster.TLSServerName != "" {
		return target, errors.New("kubeconfig target requires direct HTTPS with CA verification and no proxy/TLS-name override")
	}
	ca, decodeErr := base64.StdEncoding.Strict().DecodeString(cluster.CertificateAuthorityData)
	if decodeErr != nil {
		return target, errors.New("invalid embedded CA data")
	}
	if (len(ca) == 0) == (cluster.CertificateAuthority == "") {
		return target, errors.New("selected kubeconfig must supply exactly one CA source")
	}
	if len(ca) == 0 {
		caPath := cluster.CertificateAuthority
		if !filepath.IsAbs(caPath) {
			caPath = filepath.Join(filepath.Dir(path), caPath)
		}
		ca, err = readFile(caPath, false)
		if err != nil {
			return target, errors.New("cannot read selected kubeconfig CA file")
		}
	}
	trust, err := TrustDigest(ca)
	if err != nil {
		return target, err
	}
	return Target{Context: context, Cluster: name, Endpoint: endpoint, CATrustDigest: trust}, nil
}

// MatchTransport compares API endpoint and the complete certificate trust set,
// not labels, current-context, authentication credentials or live access.
func (target Target) MatchTransport(endpoint string, ca []byte) error {
	normalized, err := normalizeEndpoint(endpoint)
	if err != nil || normalized != target.Endpoint {
		return errors.New("selected kubeconfig endpoint differs from bound runtime authority")
	}
	trust, err := TrustDigest(ca)
	if err != nil || trust != target.CATrustDigest {
		return errors.New("selected kubeconfig CA trust differs from bound runtime authority")
	}
	return nil
}

func TrustDigest(raw []byte) (string, error) {
	certificates := map[string]bool{}
	for len(bytes.TrimSpace(raw)) != 0 {
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return "", errors.New("CA trust must contain only PEM certificates")
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", errors.New("invalid CA certificate bundle")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", errors.New("invalid CA certificate")
		}
		certificates[digest.SHA256(block.Bytes)] = true
		raw = rest
	}
	if len(certificates) == 0 {
		return "", errors.New("empty CA trust bundle")
	}
	identities := make([]string, 0, len(certificates))
	for id := range certificates {
		identities = append(identities, id)
	}
	sort.Strings(identities)
	raw, _ = json.Marshal(identities)
	return digest.SHA256(raw), nil
}

func normalizeEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("invalid Kubernetes HTTPS endpoint")
	}
	u.Host = strings.ToLower(u.Host)
	if u.Port() == "443" {
		u.Host = strings.ToLower(u.Hostname())
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	u.Path, u.RawPath = "", ""
	return u.String(), nil
}

func readFile(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1024*1024 || (private && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("kubeconfig/CA must be a bounded regular non-symlink file; kubeconfig must be private")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open explicit kubeconfig/CA")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || (private && opened.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("kubeconfig/CA changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil || len(raw) > 1024*1024 {
		return nil, errors.New("cannot read bounded kubeconfig/CA")
	}
	return raw, nil
}

func inspect(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("alias")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
				return errors.New("duplicate/non-string key")
			}
			seen[key.Value] = true
			if key.Value == "contexts" || key.Value == "clusters" || key.Value == "users" {
				sequence := node.Content[i+1]
				if sequence.Kind != yaml.SequenceNode {
					return errors.New("named entries must be a sequence")
				}
				names := map[string]bool{}
				for _, entry := range sequence.Content {
					name := ""
					if entry.Kind != yaml.MappingNode {
						return errors.New("named entry must be a mapping")
					}
					for j := 0; j < len(entry.Content); j += 2 {
						if entry.Content[j].Value == "name" && entry.Content[j+1].Tag == "!!str" {
							name = entry.Content[j+1].Value
						}
					}
					if name == "" || names[name] {
						return errors.New("missing/duplicate entry name")
					}
					names[name] = true
				}
			}
		}
	}
	for _, child := range node.Content {
		if err := inspect(child); err != nil {
			return err
		}
	}
	return nil
}
