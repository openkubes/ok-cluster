package submission

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"gopkg.in/yaml.v3"
)

const (
	ProviderAccessPolicyFormat     = "ok147-provider-access-policy/v1"
	maximumProviderKubeconfigBytes = 1024 * 1024
)

// ProviderAccessExpected is supplied from the verified staged plan and
// Contract identity. It contains no credential material.
type ProviderAccessExpected struct {
	PolicyDigest        string
	ContractIdentity    contract.Identity
	IntentRevision      string
	ExecutionFixture    string
	ManagementAuthority string
	ProviderAuthority   string
}

type providerAccessSecretPolicy struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	DataKey    string `json:"dataKey"`
	Immutable  bool   `json:"immutable"`
}

type providerAccessPolicyDocument struct {
	Format              string                     `json:"format"`
	ContractIdentity    contract.Identity          `json:"contractIdentity"`
	IntentRevision      string                     `json:"intentRevision"`
	ExecutionFixture    string                     `json:"executionFixture"`
	ManagementAuthority string                     `json:"managementAuthority"`
	ProviderAuthority   string                     `json:"providerAuthority"`
	Secret              providerAccessSecretPolicy `json:"secret"`
}

// VerifiedProviderAccessPolicy retains only non-secret policy. The source
// kubeconfig is read later, at the same runtime boundary as other credentials.
type VerifiedProviderAccessPolicy struct {
	document providerAccessPolicyDocument
	digest   string
	verified bool
}

// LoadProviderAccessPolicy verifies the public, credential-free policy bound
// as the second cluster-lifecycle stage input. It performs no credential read.
func LoadProviderAccessPolicy(path string, expected ProviderAccessExpected) (VerifiedProviderAccessPolicy, error) {
	if err := validateProviderAccessExpected(expected); err != nil {
		return VerifiedProviderAccessPolicy{}, err
	}
	raw, err := readBoundedRegularProviderFile(path, maximumProjectionArtifactBytes, false)
	if err != nil {
		return VerifiedProviderAccessPolicy{}, errors.New("read provider-access policy")
	}
	if digest.SHA256(raw) != expected.PolicyDigest {
		return VerifiedProviderAccessPolicy{}, errors.New("provider-access policy digest differs from staged input")
	}
	var document providerAccessPolicyDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return VerifiedProviderAccessPolicy{}, errors.New("decode provider-access policy")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return VerifiedProviderAccessPolicy{}, errors.New("provider-access policy has trailing content")
	}
	if document.Format != ProviderAccessPolicyFormat || document.ContractIdentity != expected.ContractIdentity ||
		document.IntentRevision != expected.IntentRevision || document.ExecutionFixture != expected.ExecutionFixture ||
		document.ManagementAuthority != expected.ManagementAuthority || document.ProviderAuthority != expected.ProviderAuthority {
		return VerifiedProviderAccessPolicy{}, errors.New("provider-access policy identity differs from expected binding")
	}
	secret := document.Secret
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Namespace != expected.ContractIdentity.Namespace ||
		secret.Name != "external-infra-kubeconfig-"+expected.ContractIdentity.Name || secret.Type != "Opaque" ||
		secret.DataKey != "kubeconfig" || !secret.Immutable {
		return VerifiedProviderAccessPolicy{}, errors.New("provider-access Secret policy is invalid")
	}
	return VerifiedProviderAccessPolicy{document: document, digest: expected.PolicyDigest, verified: true}, nil
}

func validateProviderAccessExpected(expected ProviderAccessExpected) error {
	for _, value := range []string{expected.PolicyDigest, expected.IntentRevision, expected.ExecutionFixture} {
		if !immutableDigestPattern.MatchString(value) {
			return errors.New("provider-access expected digest identity is invalid")
		}
	}
	if !validName(expected.ContractIdentity.Namespace, 63) || strings.Contains(expected.ContractIdentity.Namespace, ".") ||
		!validName(expected.ContractIdentity.Name, 253) || !validName(expected.ManagementAuthority, 63) ||
		strings.Contains(expected.ManagementAuthority, ".") || !validName(expected.ProviderAuthority, 63) ||
		strings.Contains(expected.ProviderAuthority, ".") || expected.ManagementAuthority == expected.ProviderAuthority {
		return errors.New("provider-access authority or Contract identity is invalid")
	}
	return nil
}

// MaterializeSecret reads one private 0600 kubeconfig, retains only its
// selected static context, rewrites that context namespace as required by
// external CAPK, and produces one exact immutable Secret object in memory.
// Credential bytes never enter errors or a separate public receipt.
func (policy VerifiedProviderAccessPolicy) MaterializeSecret(kubeconfigPath string) (Object, error) {
	if !policy.verified || policy.document.Format != ProviderAccessPolicyFormat || !immutableDigestPattern.MatchString(policy.digest) {
		return Object{}, errors.New("provider-access policy was not produced by verification")
	}
	raw, err := readBoundedRegularProviderFile(kubeconfigPath, maximumProviderKubeconfigBytes, true)
	if err != nil {
		return Object{}, errors.New("read provider-access credential")
	}
	rewritten, err := rewriteProviderKubeconfigNamespace(raw, policy.document.Secret.Namespace)
	if err != nil {
		return Object{}, errors.New("validate provider-access credential")
	}
	secret := policy.document.Secret
	value := map[string]any{
		"apiVersion": secret.APIVersion,
		"kind":       secret.Kind,
		"metadata": map[string]any{
			"name":      secret.Name,
			"namespace": secret.Namespace,
			"annotations": map[string]any{
				"openkubes.io/contract-name":      policy.document.ContractIdentity.Name,
				"openkubes.io/contract-namespace": policy.document.ContractIdentity.Namespace,
				"openkubes.io/intent-revision":    policy.document.IntentRevision,
				"openkubes.io/execution-fixture":  policy.document.ExecutionFixture,
				"openkubes.io/provider-plane":     policy.document.ProviderAuthority,
			},
		},
		"immutable": true,
		"type":      secret.Type,
		"data":      map[string]any{secret.DataKey: base64.StdEncoding.EncodeToString(rewritten)},
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return Object{}, errors.New("canonicalize provider-access Secret")
	}
	identity := projection.ResourceIdentity{APIVersion: "v1", Kind: "Secret", Namespace: secret.Namespace, Name: secret.Name}
	collection := "/api/v1/namespaces/" + secret.Namespace + "/secrets"
	return Object{
		Identity: identity, Digest: digest.SHA256(canonical), CollectionPath: collection,
		ObjectPath: collection + "/" + secret.Name, Raw: canonical,
	}, nil
}

func readBoundedRegularProviderFile(path string, maximum int64, private bool) ([]byte, error) {
	if path == "" {
		return nil, errors.New("path is required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("file metadata is invalid")
	}
	if private && info.Mode().Perm() != 0o600 {
		return nil, errors.New("private file mode is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open bounded file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != info.Size() || !os.SameFile(info, opened) {
		return nil, errors.New("bounded file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, errors.New("read bounded file")
	}
	return raw, nil
}

func rewriteProviderKubeconfigNamespace(raw []byte, namespace string) ([]byte, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return nil, errors.New("kubeconfig YAML is invalid")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("kubeconfig has trailing documents")
	}
	root := document.Content[0]
	if err := validateProviderYAMLNode(root); err != nil || root.Kind != yaml.MappingNode {
		return nil, errors.New("kubeconfig structure is invalid")
	}
	apiVersion := providerMappingValue(root, "apiVersion")
	kind := providerMappingValue(root, "kind")
	current := providerMappingValue(root, "current-context")
	contexts := providerMappingNode(root, "contexts")
	clusters := providerMappingNode(root, "clusters")
	users := providerMappingNode(root, "users")
	if apiVersion == nil || apiVersion.Value != "v1" || kind == nil || kind.Value != "Config" ||
		current == nil || current.Kind != yaml.ScalarNode || current.Value == "" ||
		contexts == nil || contexts.Kind != yaml.SequenceNode || clusters == nil || clusters.Kind != yaml.SequenceNode ||
		users == nil || users.Kind != yaml.SequenceNode {
		return nil, errors.New("kubeconfig identity is invalid")
	}
	clusterEntries, err := providerNamedEntries(clusters)
	if err != nil {
		return nil, errors.New("kubeconfig clusters are invalid")
	}
	userEntries, err := providerNamedEntries(users)
	if err != nil {
		return nil, errors.New("kubeconfig users are invalid")
	}
	var selected, selectedEntry *yaml.Node
	contextNames := map[string]struct{}{}
	for _, entry := range contexts.Content {
		if entry.Kind != yaml.MappingNode {
			return nil, errors.New("kubeconfig context is invalid")
		}
		name := providerMappingValue(entry, "name")
		context := providerMappingNode(entry, "context")
		if name == nil || name.Value == "" || context == nil || context.Kind != yaml.MappingNode {
			return nil, errors.New("kubeconfig context is invalid")
		}
		if _, exists := contextNames[name.Value]; exists {
			return nil, errors.New("kubeconfig context name is duplicated")
		}
		contextNames[name.Value] = struct{}{}
		if name != nil && name.Value == current.Value {
			selected = context
			selectedEntry = entry
		}
	}
	if selected == nil || selected.Kind != yaml.MappingNode {
		return nil, errors.New("kubeconfig current context is missing")
	}
	cluster := providerMappingValue(selected, "cluster")
	user := providerMappingValue(selected, "user")
	if cluster == nil || user == nil || cluster.Value == "" || user.Value == "" || selectedEntry == nil {
		return nil, errors.New("kubeconfig current context references are invalid")
	}
	selectedCluster := clusterEntries[cluster.Value]
	selectedUser := userEntries[user.Value]
	if selectedCluster == nil || selectedUser == nil {
		return nil, errors.New("kubeconfig current context references are invalid")
	}
	if err := validateStaticProviderIdentity(selectedCluster, selectedUser); err != nil {
		return nil, err
	}
	if existing := providerMappingValue(selected, "namespace"); existing != nil {
		existing.Tag, existing.Kind, existing.Value = "!!str", yaml.ScalarNode, namespace
	} else {
		selected.Content = append(selected.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "namespace"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: namespace},
		)
	}
	// The provider Secret must not transport credentials or endpoints unrelated
	// to the selected authority, even when the source kubeconfig contains them.
	contexts.Content = []*yaml.Node{selectedEntry}
	clusters.Content = []*yaml.Node{selectedCluster}
	users.Content = []*yaml.Node{selectedUser}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, errors.New("encode kubeconfig")
	}
	if err := encoder.Close(); err != nil {
		return nil, errors.New("close kubeconfig encoder")
	}
	return output.Bytes(), nil
}

func validateStaticProviderIdentity(clusterEntry, userEntry *yaml.Node) error {
	cluster := providerMappingNode(clusterEntry, "cluster")
	user := providerMappingNode(userEntry, "user")
	server := providerMappingValue(cluster, "server")
	caData := providerMappingValue(cluster, "certificate-authority-data")
	if cluster == nil || user == nil || server == nil || !strings.HasPrefix(server.Value, "https://") ||
		caData == nil || caData.Value == "" || providerMappingNode(cluster, "proxy-url") != nil ||
		providerMappingNode(cluster, "certificate-authority") != nil ||
		providerMappingNode(cluster, "insecure-skip-tls-verify") != nil {
		return errors.New("kubeconfig selected cluster transport is not static and verified")
	}
	for _, forbidden := range []string{
		"exec", "auth-provider", "tokenFile", "token-file", "client-certificate", "client-key",
		"username", "password", "as", "as-uid", "as-groups", "as-user-extra",
	} {
		if providerMappingNode(user, forbidden) != nil {
			return errors.New("kubeconfig selected user authentication is not static and self-contained")
		}
	}
	certificate := providerMappingValue(user, "client-certificate-data")
	key := providerMappingValue(user, "client-key-data")
	token := providerMappingValue(user, "token")
	certificateMode := certificate != nil && certificate.Value != "" && key != nil && key.Value != ""
	tokenMode := token != nil && token.Value != ""
	if certificateMode == tokenMode {
		return errors.New("kubeconfig selected user authentication mode is ambiguous")
	}
	return nil
}

func validateProviderYAMLNode(node *yaml.Node) error {
	if node == nil || node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("YAML aliases and anchors are not accepted")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]struct{}{}
		for index := 0; index < len(node.Content); index += 2 {
			if index+1 >= len(node.Content) || node.Content[index].Kind != yaml.ScalarNode {
				return errors.New("YAML mapping is invalid")
			}
			key := node.Content[index].Value
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate YAML key")
			}
			seen[key] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := validateProviderYAMLNode(child); err != nil {
			return err
		}
	}
	return nil
}

func providerMappingNode(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func providerMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	value := providerMappingNode(mapping, key)
	if value == nil || value.Kind != yaml.ScalarNode {
		return nil
	}
	return value
}

func providerNamedEntries(sequence *yaml.Node) (map[string]*yaml.Node, error) {
	entries := make(map[string]*yaml.Node, len(sequence.Content))
	for _, entry := range sequence.Content {
		if entry.Kind != yaml.MappingNode {
			return nil, errors.New("named entry is not a mapping")
		}
		name := providerMappingValue(entry, "name")
		if name == nil || name.Value == "" || entries[name.Value] != nil {
			return nil, errors.New("named entry identity is invalid")
		}
		entries[name.Value] = entry
	}
	return entries, nil
}
