package submission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"gopkg.in/yaml.v3"
)

const (
	TargetRegistrationPlanFormat       = "ok147-bounded-target-registration-plan/v1"
	maximumTargetRegistrationBytes     = 512 * 1024
	RegistrationCAPIUIDPlaceholder     = "RUNTIME-CAPI-UID-REQUIRED"
	RegistrationWorkloadUIDPlaceholder = "RUNTIME-WORKLOAD-KUBE-SYSTEM-UID-REQUIRED"
	RegistrationCADigestPlaceholder    = "RUNTIME-WORKLOAD-CA-DIGEST-REQUIRED"
	RegistrationExpirationPlaceholder  = "RUNTIME-TOKEN-EXPIRATION-REQUIRED"
	RegistrationEndpointPlaceholder    = "RUNTIME-HTTPS-ENDPOINT-REQUIRED"
	RegistrationConfigPlaceholder      = "RUNTIME-IN-MEMORY-MATERIALIZATION-ONLY"
	// RuntimeTargetIdentityDigestPlaceholder keeps the pre-runtime projection
	// independent of the CAPI Cluster UID, which Kubernetes assigns only after
	// the lifecycle stage. The verified lifecycle receipt supplies the concrete
	// digest before any target-registration object can be submitted.
	RuntimeTargetIdentityDigestPlaceholder = "RUNTIME-TARGET-IDENTITY-DIGEST-REQUIRED"
)

type TargetRegistrationExpected struct {
	ArtifactDigest       string
	ContractIdentity     contract.Identity
	IntentRevision       string
	PlatformRevision     string
	ExecutionFixture     string
	TargetIdentityDigest string
	ArgoAuthority        string
	ArgoNamespace        string
	ProjectName          string
	RegistrationName     string
	TargetName           string
	SourceRepository     string
	TargetNamespaces     []string
}

type RegistrationTemplate struct {
	Identity       projection.ResourceIdentity `json:"identity"`
	Digest         string                      `json:"digest"`
	CollectionPath string                      `json:"collectionPath"`
	ObjectPath     string                      `json:"objectPath"`
	Raw            json.RawMessage             `json:"-"`
}

type TargetRegistrationPlan struct {
	Format               string               `json:"format"`
	IntentRevision       string               `json:"intentRevision"`
	PlatformRevision     string               `json:"platformRevision"`
	ExecutionFixture     string               `json:"executionFixture"`
	TargetIdentityDigest string               `json:"targetIdentityDigest"`
	ArtifactDigest       string               `json:"artifactDigest"`
	Authority            string               `json:"authority"`
	Project              Object               `json:"project"`
	Registration         RegistrationTemplate `json:"registration"`
	MutationAllowed      bool                 `json:"mutationAllowed"`
}

// LoadTargetRegistration verifies one AppProject plus one credential-free
// Argo cluster Secret template. It performs no materialization or API call.
func LoadTargetRegistration(path string, expected TargetRegistrationExpected) (TargetRegistrationPlan, error) {
	if err := validateTargetRegistrationExpected(expected); err != nil {
		return TargetRegistrationPlan{}, err
	}
	raw, err := readTargetRegistrationArtifact(path)
	if err != nil {
		return TargetRegistrationPlan{}, err
	}
	if digest.SHA256(raw) != expected.ArtifactDigest {
		return TargetRegistrationPlan{}, errors.New("target-registration artifact digest differs from staged input")
	}
	values, err := decodeTargetRegistrationDocuments(raw)
	if err != nil {
		return TargetRegistrationPlan{}, err
	}
	project, err := validateTargetRegistrationProject(values[0], expected)
	if err != nil {
		return TargetRegistrationPlan{}, fmt.Errorf("target-registration AppProject: %w", err)
	}
	registration, err := validateTargetRegistrationSecret(values[1], expected)
	if err != nil {
		return TargetRegistrationPlan{}, fmt.Errorf("target-registration Secret template: %w", err)
	}
	return TargetRegistrationPlan{
		Format: TargetRegistrationPlanFormat, IntentRevision: expected.IntentRevision,
		PlatformRevision: expected.PlatformRevision, ExecutionFixture: expected.ExecutionFixture,
		TargetIdentityDigest: expected.TargetIdentityDigest, ArtifactDigest: expected.ArtifactDigest,
		Authority: expected.ArgoAuthority, Project: project, Registration: registration, MutationAllowed: false,
	}, nil
}

func validateTargetRegistrationExpected(expected TargetRegistrationExpected) error {
	for _, value := range []string{expected.ArtifactDigest, expected.IntentRevision, expected.PlatformRevision, expected.ExecutionFixture, expected.TargetIdentityDigest} {
		if !immutableDigestPattern.MatchString(value) {
			return errors.New("target-registration expected digest identity is invalid")
		}
	}
	if !validName(expected.ContractIdentity.Namespace, 63) || !validName(expected.ContractIdentity.Name, 253) || !validName(expected.ArgoAuthority, 63) || !validName(expected.ArgoNamespace, 63) || !validName(expected.ProjectName, 253) || !validName(expected.RegistrationName, 253) || !validName(expected.TargetName, 253) {
		return errors.New("target-registration expected identity is invalid")
	}
	repository, err := url.Parse(expected.SourceRepository)
	if err != nil || repository.Scheme != "https" || repository.Host == "" || repository.User != nil || repository.RawQuery != "" || repository.Fragment != "" {
		return errors.New("target-registration source repository is invalid")
	}
	if len(expected.TargetNamespaces) != 2 || expected.TargetNamespaces[0] != "ok-observability" || expected.TargetNamespaces[1] != "kube-system" {
		return errors.New("target-registration target namespaces must be the exact MVP set")
	}
	return nil
}

func readTargetRegistrationArtifact(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("target-registration artifact path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect target-registration artifact: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumTargetRegistrationBytes {
		return nil, errors.New("target-registration artifact metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target-registration artifact: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumTargetRegistrationBytes+1))
	if err != nil || len(raw) > maximumTargetRegistrationBytes {
		return nil, errors.New("read bounded target-registration artifact")
	}
	return raw, nil
}

func decodeTargetRegistrationDocuments(raw []byte) ([]map[string]any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	values := make([]map[string]any, 0, 2)
	for {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode target-registration YAML: %w", err)
		}
		if len(document.Content) == 0 {
			continue
		}
		if err := rejectAliases(document.Content[0]); err != nil {
			return nil, err
		}
		var decoded any
		if err := document.Content[0].Decode(&decoded); err != nil {
			return nil, errors.New("decode target-registration object")
		}
		converted, err := jsonValue(decoded)
		if err != nil {
			return nil, err
		}
		value, ok := converted.(map[string]any)
		if !ok {
			return nil, errors.New("target-registration document is not a Kubernetes object")
		}
		values = append(values, value)
	}
	if len(values) != 2 {
		return nil, fmt.Errorf("target-registration artifact contains %d objects, expected exactly 2", len(values))
	}
	return values, nil
}

func validateTargetRegistrationProject(value map[string]any, expected TargetRegistrationExpected) (Object, error) {
	if err := rejectTargetAccessUnknownKeys(value, "AppProject", "apiVersion", "kind", "metadata", "spec"); err != nil {
		return Object{}, err
	}
	metadata, identity, err := targetRegistrationMetadata(value, "argoproj.io/v1alpha1", "AppProject", expected.ArgoNamespace, expected.ProjectName)
	if err != nil {
		return Object{}, err
	}
	if err := validateTargetRegistrationAnnotations(metadata, expected, false); err != nil {
		return Object{}, err
	}
	spec, ok := value["spec"].(map[string]any)
	if !ok {
		return Object{}, errors.New("AppProject spec is missing")
	}
	if err := rejectTargetAccessUnknownKeys(spec, "AppProject spec", "description", "permitOnlyProjectScopedClusters", "sourceRepos", "sourceNamespaces", "destinations", "clusterResourceWhitelist", "namespaceResourceWhitelist", "orphanedResources"); err != nil {
		return Object{}, err
	}
	if spec["permitOnlyProjectScopedClusters"] != true || !exactStringList(spec["sourceRepos"], []string{expected.SourceRepository}) || !exactStringList(spec["sourceNamespaces"], []string{expected.ArgoNamespace}) {
		return Object{}, errors.New("AppProject source or project-scoping boundary differs")
	}
	destinations, ok := spec["destinations"].([]any)
	if !ok || len(destinations) != 2 {
		return Object{}, errors.New("AppProject destinations differ from exact target scope")
	}
	for index, namespace := range expected.TargetNamespaces {
		destination, ok := destinations[index].(map[string]any)
		if !ok || len(destination) != 2 || text(destination["name"]) != expected.TargetName || text(destination["namespace"]) != namespace {
			return Object{}, errors.New("AppProject destination differs from exact target scope")
		}
	}
	if err := validateTargetRegistrationResources(spec["clusterResourceWhitelist"], true); err != nil {
		return Object{}, err
	}
	if err := validateTargetRegistrationResources(spec["namespaceResourceWhitelist"], false); err != nil {
		return Object{}, err
	}
	orphaned, ok := spec["orphanedResources"].(map[string]any)
	if !ok || len(orphaned) != 1 || orphaned["warn"] != true {
		return Object{}, errors.New("AppProject orphan warning boundary is invalid")
	}
	return targetRegistrationObject(value, identity)
}

func validateTargetRegistrationSecret(value map[string]any, expected TargetRegistrationExpected) (RegistrationTemplate, error) {
	if err := rejectTargetAccessUnknownKeys(value, "Secret", "apiVersion", "kind", "metadata", "type", "stringData"); err != nil {
		return RegistrationTemplate{}, err
	}
	metadata, identity, err := targetRegistrationMetadata(value, "v1", "Secret", expected.ArgoNamespace, expected.RegistrationName)
	if err != nil {
		return RegistrationTemplate{}, err
	}
	if value["type"] != "Opaque" {
		return RegistrationTemplate{}, errors.New("registration Secret type is invalid")
	}
	labels, ok := metadata["labels"].(map[string]any)
	if !ok || len(labels) != 1 || labels["argocd.argoproj.io/secret-type"] != "cluster" {
		return RegistrationTemplate{}, errors.New("registration Secret label is invalid")
	}
	if err := validateTargetRegistrationAnnotations(metadata, expected, true); err != nil {
		return RegistrationTemplate{}, err
	}
	data, ok := value["stringData"].(map[string]any)
	if !ok || len(data) != 6 || text(data["name"]) != expected.TargetName || text(data["server"]) != RegistrationEndpointPlaceholder || text(data["namespaces"]) != strings.Join(expected.TargetNamespaces, ",") || text(data["clusterResources"]) != "true" || text(data["project"]) != expected.ProjectName || text(data["config"]) != RegistrationConfigPlaceholder {
		return RegistrationTemplate{}, errors.New("registration Secret materialization boundary differs")
	}
	object, err := targetRegistrationObject(value, identity)
	if err != nil {
		return RegistrationTemplate{}, err
	}
	return RegistrationTemplate{Identity: object.Identity, Digest: object.Digest, CollectionPath: object.CollectionPath, ObjectPath: object.ObjectPath, Raw: object.Raw}, nil
}

func targetRegistrationMetadata(value map[string]any, apiVersion, kind, namespace, name string) (map[string]any, projection.ResourceIdentity, error) {
	metadata, ok := value["metadata"].(map[string]any)
	if !ok {
		return nil, projection.ResourceIdentity{}, errors.New("metadata is missing")
	}
	if err := rejectTargetAccessUnknownKeys(metadata, "metadata", "name", "namespace", "labels", "annotations"); err != nil {
		return nil, projection.ResourceIdentity{}, err
	}
	identity := projection.ResourceIdentity{APIVersion: text(value["apiVersion"]), Kind: text(value["kind"]), Namespace: text(metadata["namespace"]), Name: text(metadata["name"])}
	if identity != (projection.ResourceIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name}) {
		return nil, projection.ResourceIdentity{}, errors.New("object identity differs from expected registration scope")
	}
	return metadata, identity, nil
}

func validateTargetRegistrationAnnotations(metadata map[string]any, expected TargetRegistrationExpected, runtime bool) error {
	annotations, ok := metadata["annotations"].(map[string]any)
	want := map[string]string{
		"openkubes.io/intent-revision":        expected.IntentRevision,
		"openkubes.io/platform-revision":      expected.PlatformRevision,
		"openkubes.io/execution-fixture":      expected.ExecutionFixture,
		"openkubes.io/target-identity-digest": RuntimeTargetIdentityDigestPlaceholder,
	}
	if runtime {
		want["openkubes.io/capi-cluster-uid"] = RegistrationCAPIUIDPlaceholder
		want["openkubes.io/workload-kube-system-uid"] = RegistrationWorkloadUIDPlaceholder
		want["openkubes.io/workload-api-ca-sha256"] = RegistrationCADigestPlaceholder
		want["openkubes.io/token-expiration"] = RegistrationExpirationPlaceholder
	}
	if !ok || len(annotations) != len(want) {
		return errors.New("registration annotations differ from exact identity set")
	}
	for key, value := range want {
		if text(annotations[key]) != value {
			return errors.New("registration annotation differs from verified identity")
		}
	}
	// Materialize only the lifecycle-derived identity carrier. All other
	// runtime Secret fields retain their explicit placeholders until the
	// credential-bearing in-memory materialization step.
	annotations["openkubes.io/target-identity-digest"] = expected.TargetIdentityDigest
	return nil
}

func validateTargetRegistrationResources(value any, clusterScoped bool) error {
	items, ok := value.([]any)
	if !ok || len(items) == 0 || len(items) > 64 {
		return errors.New("AppProject resource allow-list is invalid")
	}
	previous := ""
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok || len(entry) != 2 {
			return errors.New("AppProject resource allow-list entry is invalid")
		}
		group, kind := text(entry["group"]), text(entry["kind"])
		if kind == "" || group == "*" || kind == "*" || strings.ContainsAny(group+kind, "\r\n") {
			return errors.New("AppProject resource allow-list contains a wildcard or invalid entry")
		}
		key := group + "/" + kind
		if previous != "" && key <= previous {
			return errors.New("AppProject resource allow-list is not uniquely sorted")
		}
		previous = key
	}
	_ = clusterScoped
	return nil
}

func exactStringList(value any, expected []string) bool {
	items, ok := value.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	for index := range expected {
		if text(items[index]) != expected[index] {
			return false
		}
	}
	return true
}

func targetRegistrationObject(value map[string]any, identity projection.ResourceIdentity) (Object, error) {
	raw, err := canonicalJSON(value)
	if err != nil {
		return Object{}, errors.New("encode target-registration object")
	}
	resource := "secrets"
	groupPath := "/api/v1"
	if identity.Kind == "AppProject" {
		resource = "appprojects"
		groupPath = "/apis/argoproj.io/v1alpha1"
	}
	collection := groupPath + "/namespaces/" + identity.Namespace + "/" + resource
	return Object{Identity: identity, Digest: digest.SHA256(raw), CollectionPath: collection, ObjectPath: collection + "/" + identity.Name, Raw: raw}, nil
}
