package submission

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"gopkg.in/yaml.v3"
)

const EnablementPlanFormat = "ok147-bounded-enablement-plan/v1"

var immutableDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// EnablementExpected is independently supplied from the verified execution
// fixture and staged plan. The renderer remains responsible for the object.
type EnablementExpected struct {
	ArtifactDigest      string
	ContractIdentity    contract.Identity
	IntentRevision      string
	EnablementRevision  string
	ExecutionFixture    string
	ManagementAuthority string
	ObjectIdentity      projection.ResourceIdentity
}

// EnablementPlan contains exactly one externally rendered HelmChartProxy.
// It is a verified desired-state projection, not authorization to submit it.
type EnablementPlan struct {
	Format             string `json:"format"`
	IntentRevision     string `json:"intentRevision"`
	EnablementRevision string `json:"enablementRevision"`
	ExecutionFixture   string `json:"executionFixture"`
	ArtifactDigest     string `json:"artifactDigest"`
	MutationAllowed    bool   `json:"mutationAllowed"`
	Management         Plane  `json:"management"`
}

// LoadEnablement verifies one bounded renderer artifact without rendering,
// contacting Kubernetes or granting mutation authority.
func LoadEnablement(path string, expected EnablementExpected) (EnablementPlan, error) {
	if err := validateEnablementExpected(expected); err != nil {
		return EnablementPlan{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return EnablementPlan{}, fmt.Errorf("inspect enablement artifact: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumProjectionArtifactBytes {
		return EnablementPlan{}, errors.New("enablement artifact metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return EnablementPlan{}, fmt.Errorf("open enablement artifact: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumProjectionArtifactBytes+1))
	if err != nil || len(raw) > maximumProjectionArtifactBytes {
		return EnablementPlan{}, errors.New("read bounded enablement artifact")
	}
	if actual := digest.SHA256(raw); actual != expected.ArtifactDigest {
		return EnablementPlan{}, errors.New("enablement artifact digest differs from staged input")
	}
	object, err := decodeEnablementObject(raw, expected)
	if err != nil {
		return EnablementPlan{}, err
	}
	return EnablementPlan{
		Format: EnablementPlanFormat, IntentRevision: expected.IntentRevision,
		EnablementRevision: expected.EnablementRevision, ExecutionFixture: expected.ExecutionFixture,
		ArtifactDigest: expected.ArtifactDigest, MutationAllowed: false,
		Management: Plane{Identity: expected.ManagementAuthority, Role: "enablement-desired-state-writer", Objects: []Object{object}},
	}, nil
}

func validateEnablementExpected(expected EnablementExpected) error {
	for _, value := range []string{expected.ArtifactDigest, expected.IntentRevision, expected.EnablementRevision, expected.ExecutionFixture} {
		if !immutableDigestPattern.MatchString(value) {
			return errors.New("enablement expected digest identity is invalid")
		}
	}
	if !validName(expected.ContractIdentity.Namespace, 63) || strings.Contains(expected.ContractIdentity.Namespace, ".") || !validName(expected.ContractIdentity.Name, 253) {
		return errors.New("enablement Contract identity is invalid")
	}
	if !validName(expected.ManagementAuthority, 63) || strings.Contains(expected.ManagementAuthority, ".") {
		return errors.New("enablement management authority is invalid")
	}
	identity := expected.ObjectIdentity
	if identity.APIVersion != "addons.cluster.x-k8s.io/v1alpha1" || identity.Kind != "HelmChartProxy" || identity.Namespace != expected.ContractIdentity.Namespace || !validName(identity.Name, 253) {
		return errors.New("enablement object identity is invalid")
	}
	return nil
}

func decodeEnablementObject(raw []byte, expected EnablementExpected) (Object, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return Object{}, fmt.Errorf("decode enablement YAML: %w", err)
	}
	if len(document.Content) == 0 {
		return Object{}, errors.New("enablement artifact is empty")
	}
	if err := rejectAliases(document.Content[0]); err != nil {
		return Object{}, err
	}
	var decoded any
	if err := document.Content[0].Decode(&decoded); err != nil {
		return Object{}, fmt.Errorf("decode enablement object: %w", err)
	}
	value, err := jsonValue(decoded)
	if err != nil {
		return Object{}, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return Object{}, errors.New("enablement document is not a Kubernetes object")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return Object{}, fmt.Errorf("decode trailing enablement YAML: %w", err)
		}
		if len(trailing.Content) != 0 {
			return Object{}, errors.New("enablement artifact must contain exactly one object")
		}
	}
	return validateEnablementObject(object, expected)
}

func validateEnablementObject(value map[string]any, expected EnablementExpected) (Object, error) {
	if _, exists := value["status"]; exists {
		return Object{}, errors.New("enablement object must not contain status")
	}
	metadata, _ := value["metadata"].(map[string]any)
	identity := projection.ResourceIdentity{
		APIVersion: text(value["apiVersion"]), Kind: text(value["kind"]),
		Name: text(metadata["name"]), Namespace: text(metadata["namespace"]),
	}
	if identity != expected.ObjectIdentity {
		return Object{}, errors.New("enablement object identity differs from the staged input")
	}
	for _, forbidden := range []string{"generateName", "uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "managedFields", "ownerReferences", "finalizers"} {
		if _, exists := metadata[forbidden]; exists {
			return Object{}, fmt.Errorf("enablement metadata.%s is not accepted", forbidden)
		}
	}
	annotations, _ := metadata["annotations"].(map[string]any)
	required := map[string]string{
		"openkubes.io/contract-name":       expected.ContractIdentity.Name,
		"openkubes.io/contract-namespace":  expected.ContractIdentity.Namespace,
		"openkubes.io/intent-revision":     expected.IntentRevision,
		"openkubes.io/enablement-revision": expected.EnablementRevision,
		"openkubes.io/execution-fixture":   expected.ExecutionFixture,
		"openkubes.io/digest-enforcement":  "external-evidence-required",
	}
	for key, want := range required {
		if text(annotations[key]) != want {
			return Object{}, fmt.Errorf("enablement object lacks exact %s carrier", key)
		}
	}
	for _, key := range []string{"openkubes.io/oci-manifest-digest", "openkubes.io/chart-artifact-digest", "openkubes.io/values-digest"} {
		if !immutableDigestPattern.MatchString(text(annotations[key])) {
			return Object{}, fmt.Errorf("enablement object lacks immutable %s", key)
		}
	}
	if err := validateHelmChartProxySpec(value["spec"]); err != nil {
		return Object{}, err
	}
	collection := "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/" + identity.Namespace + "/helmchartproxies"
	canonical, err := canonicalJSON(value)
	if err != nil {
		return Object{}, err
	}
	return Object{Identity: identity, Digest: digest.SHA256(canonical), CollectionPath: collection, ObjectPath: collection + "/" + identity.Name, Raw: canonical}, nil
}

func validateHelmChartProxySpec(raw any) error {
	spec, ok := raw.(map[string]any)
	if !ok {
		return errors.New("enablement HelmChartProxy spec is missing")
	}
	selector, _ := spec["clusterSelector"].(map[string]any)
	labels, _ := selector["matchLabels"].(map[string]any)
	if len(labels) == 0 || len(selector) != 1 {
		return errors.New("enablement cluster selector must use non-empty matchLabels only")
	}
	for key, value := range labels {
		if key == "" || text(value) == "" {
			return errors.New("enablement cluster selector label is invalid")
		}
	}
	for _, key := range []string{"chartName", "releaseName", "namespace", "version", "valuesTemplate"} {
		if strings.TrimSpace(text(spec[key])) == "" {
			return fmt.Errorf("enablement HelmChartProxy spec.%s is required", key)
		}
	}
	repo := text(spec["repoURL"])
	if len(repo) <= len("oci://") || !strings.HasPrefix(repo, "oci://") || strings.ContainsAny(repo, " \t\r\n") {
		return errors.New("enablement chart repository must be an explicit OCI source")
	}
	if strings.EqualFold(text(spec["version"]), "latest") {
		return errors.New("enablement chart version must be immutable")
	}
	if text(spec["reconcileStrategy"]) != "Continuous" {
		return errors.New("enablement reconcile strategy must be Continuous")
	}
	options, _ := spec["options"].(map[string]any)
	for _, key := range []string{"atomic", "wait", "waitForJobs"} {
		if enabled, _ := options[key].(bool); !enabled {
			return fmt.Errorf("enablement Helm option %s must be true", key)
		}
	}
	return nil
}
