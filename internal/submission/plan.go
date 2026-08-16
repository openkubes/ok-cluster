// Package submission turns an already verified renderer projection into a
// bounded exact-create plan. It never renders Contract intent and accepts only
// the resource kinds required by the OK-141 CreateCluster reference path.
package submission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"gopkg.in/yaml.v3"
)

const PlanFormat = "ok147-bounded-submission-plan/v1"

const maximumProjectionArtifactBytes = 4 * 1024 * 1024

// Object is one exact, digest-bound Kubernetes create candidate.
type Object struct {
	Identity       projection.ResourceIdentity `json:"identity"`
	Digest         string                      `json:"digest"`
	CollectionPath string                      `json:"collectionPath"`
	ObjectPath     string                      `json:"objectPath"`
	Raw            json.RawMessage             `json:"-"`
}

// Plane is a submission group owned by exactly one authority plane.
type Plane struct {
	Identity string   `json:"identity"`
	Role     string   `json:"role"`
	Objects  []Object `json:"objects"`
}

// Plan preserves the authority split from the verified projection.
type Plan struct {
	Format             string `json:"format"`
	IntentRevision     string `json:"intentRevision"`
	AuthorityMapDigest string `json:"authorityMapDigest"`
	Infrastructure     Plane  `json:"infrastructure"`
	Management         Plane  `json:"management"`
}

// Load re-reads and re-verifies the two renderer artifacts to close the
// verify/use gap. Resource identity, order, revision metadata and REST routes
// must all match the verified authority map.
func Load(root string, binding projection.Binding) (Plan, error) {
	if binding.Format != projection.BindingFormat {
		return Plan{}, fmt.Errorf("projection binding format %q is not supported", binding.Format)
	}
	if root == "" {
		return Plan{}, errors.New("projection root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return Plan{}, fmt.Errorf("resolve projection root: %w", err)
	}
	if binding.InfrastructurePlane.Identity == binding.ManagementPlane.Identity {
		return Plan{}, errors.New("submission authority identities must differ")
	}
	binding, err = projection.ReverifyAtUse(abs, binding)
	if err != nil {
		return Plan{}, fmt.Errorf("reverify projection at use: %w", err)
	}
	infrastructure, err := loadPlane(abs, "ok-infra-prerequisites.yaml", binding.InfrastructurePlane, binding, binding.IntentRevision)
	if err != nil {
		return Plan{}, fmt.Errorf("infrastructure submission plane: %w", err)
	}
	management, err := loadPlane(abs, "ok-mgmt-lifecycle.yaml", binding.ManagementPlane, binding, binding.IntentRevision)
	if err != nil {
		return Plan{}, fmt.Errorf("management submission plane: %w", err)
	}
	return Plan{
		Format:             PlanFormat,
		IntentRevision:     binding.IntentRevision,
		AuthorityMapDigest: binding.AuthorityMapDigest,
		Infrastructure:     infrastructure,
		Management:         management,
	}, nil
}

func loadPlane(root, artifactName string, expected projection.Plane, binding projection.Binding, revision string) (Plane, error) {
	if expected.ResourceCount <= 0 || expected.ResourceCount != len(expected.Resources) {
		return Plane{}, errors.New("verified projection plane has no complete resource identities")
	}
	expectedDigest, ok := artifactDigest(binding.Artifacts, artifactName)
	if !ok {
		return Plane{}, fmt.Errorf("verified projection does not bind %s", artifactName)
	}
	raw, err := readBoundedArtifact(filepath.Join(root, artifactName))
	if err != nil {
		return Plane{}, err
	}
	if actual := digest.SHA256(raw); actual != expectedDigest {
		return Plane{}, fmt.Errorf("projection artifact %s changed after verification", artifactName)
	}
	objects, err := decodeObjects(raw, expected.Resources, binding.ContractIdentity, revision)
	if err != nil {
		return Plane{}, err
	}
	return Plane{Identity: expected.Identity, Role: expected.Role, Objects: objects}, nil
}

func artifactDigest(artifacts []projection.Artifact, name string) (string, bool) {
	for _, artifact := range artifacts {
		if artifact.Name == name {
			return artifact.Digest, true
		}
	}
	return "", false
}

func readBoundedArtifact(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read projection artifact: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("inspect projection artifact")
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumProjectionArtifactBytes {
		return nil, errors.New("projection artifact metadata is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumProjectionArtifactBytes+1))
	if err != nil || len(raw) > maximumProjectionArtifactBytes {
		return nil, errors.New("read bounded projection artifact")
	}
	return raw, nil
}

func decodeObjects(raw []byte, expected []projection.ResourceIdentity, contractIdentity contract.Identity, revision string) ([]Object, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	objects := make([]Object, 0, len(expected))
	for {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode projection YAML: %w", err)
		}
		if len(document.Content) == 0 {
			continue
		}
		if err := rejectAliases(document.Content[0]); err != nil {
			return nil, err
		}
		var decoded any
		if err := document.Content[0].Decode(&decoded); err != nil {
			return nil, fmt.Errorf("decode projection object: %w", err)
		}
		value, err := jsonValue(decoded)
		if err != nil {
			return nil, err
		}
		objectMap, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("projection document is not a Kubernetes object")
		}
		object, err := validateObject(objectMap, contractIdentity, revision)
		if err != nil {
			return nil, fmt.Errorf("projection document %d: %w", len(objects)+1, err)
		}
		objects = append(objects, object)
	}
	if len(objects) != len(expected) {
		return nil, fmt.Errorf("projection contains %d objects, authority map requires %d", len(objects), len(expected))
	}
	for index := range expected {
		if objects[index].Identity != expected[index] {
			return nil, fmt.Errorf("projection object %d identity %#v differs from authority map %#v", index+1, objects[index].Identity, expected[index])
		}
	}
	return objects, nil
}

func rejectAliases(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("projection YAML aliases and anchors are not accepted")
	}
	for _, child := range node.Content {
		if err := rejectAliases(child); err != nil {
			return err
		}
	}
	return nil
}

func jsonValue(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			converted, err := jsonValue(child)
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	case map[any]any:
		result := make(map[string]any, len(typed))
		for rawKey, child := range typed {
			key, ok := rawKey.(string)
			if !ok {
				return nil, errors.New("projection YAML contains a non-string map key")
			}
			converted, err := jsonValue(child)
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			converted, err := jsonValue(child)
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	case string, bool, nil, int, int64, uint64, float64:
		return typed, nil
	default:
		reflected := reflect.ValueOf(value)
		switch reflected.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return reflected.Int(), nil
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return reflected.Uint(), nil
		case reflect.Float32, reflect.Float64:
			return reflected.Float(), nil
		default:
			return nil, fmt.Errorf("projection YAML value type %T is not JSON-compatible", value)
		}
	}
}

func validateObject(value map[string]any, identity contract.Identity, revision string) (Object, error) {
	if _, exists := value["status"]; exists {
		return Object{}, errors.New("projection object must not contain status")
	}
	apiVersion, _ := value["apiVersion"].(string)
	kind, _ := value["kind"].(string)
	metadata, _ := value["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	resourceIdentity := projection.ResourceIdentity{APIVersion: apiVersion, Kind: kind, Name: name, Namespace: namespace}
	if apiVersion == "" || kind == "" || name == "" {
		return Object{}, errors.New("projection object identity is incomplete")
	}
	for _, forbidden := range []string{"generateName", "uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "managedFields", "ownerReferences", "finalizers"} {
		if _, exists := metadata[forbidden]; exists {
			return Object{}, fmt.Errorf("projection metadata.%s is not accepted", forbidden)
		}
	}
	annotations, _ := metadata["annotations"].(map[string]any)
	if annotations["openkubes.io/contract-name"] != identity.Name || annotations["openkubes.io/contract-namespace"] != identity.Namespace || annotations["openkubes.io/intent-revision"] != revision {
		return Object{}, errors.New("projection object lacks exact contract and intent annotations")
	}
	collectionPath, objectPath, err := resourcePaths(resourceIdentity)
	if err != nil {
		return Object{}, err
	}
	raw, err := canonicalJSON(value)
	if err != nil {
		return Object{}, err
	}
	return Object{Identity: resourceIdentity, Digest: digest.SHA256(raw), CollectionPath: collectionPath, ObjectPath: objectPath, Raw: raw}, nil
}

type route struct {
	group      string
	version    string
	resource   string
	namespaced bool
}

var allowedRoutes = map[string]route{
	"v1|Namespace":                                                     {version: "v1", resource: "namespaces"},
	"rbac.authorization.k8s.io/v1|Role":                                {group: "rbac.authorization.k8s.io", version: "v1", resource: "roles", namespaced: true},
	"rbac.authorization.k8s.io/v1|RoleBinding":                         {group: "rbac.authorization.k8s.io", version: "v1", resource: "rolebindings", namespaced: true},
	"cluster.x-k8s.io/v1beta2|Cluster":                                 {group: "cluster.x-k8s.io", version: "v1beta2", resource: "clusters", namespaced: true},
	"cluster.x-k8s.io/v1beta2|MachineDeployment":                       {group: "cluster.x-k8s.io", version: "v1beta2", resource: "machinedeployments", namespaced: true},
	"infrastructure.cluster.x-k8s.io/v1alpha1|KubevirtCluster":         {group: "infrastructure.cluster.x-k8s.io", version: "v1alpha1", resource: "kubevirtclusters", namespaced: true},
	"infrastructure.cluster.x-k8s.io/v1alpha1|KubevirtMachineTemplate": {group: "infrastructure.cluster.x-k8s.io", version: "v1alpha1", resource: "kubevirtmachinetemplates", namespaced: true},
	"controlplane.cluster.x-k8s.io/v1alpha3|TalosControlPlane":         {group: "controlplane.cluster.x-k8s.io", version: "v1alpha3", resource: "taloscontrolplanes", namespaced: true},
	"bootstrap.cluster.x-k8s.io/v1alpha3|TalosConfigTemplate":          {group: "bootstrap.cluster.x-k8s.io", version: "v1alpha3", resource: "talosconfigtemplates", namespaced: true},
}

func resourcePaths(identity projection.ResourceIdentity) (string, string, error) {
	route, ok := allowedRoutes[identity.APIVersion+"|"+identity.Kind]
	if !ok {
		return "", "", fmt.Errorf("resource %s %s is not in the CreateCluster submission allow-list", identity.APIVersion, identity.Kind)
	}
	if !validName(identity.Name, 253) {
		return "", "", errors.New("projection resource name is invalid")
	}
	base := "/api/" + route.version
	if route.group != "" {
		base = "/apis/" + route.group + "/" + route.version
	}
	if route.namespaced {
		if !validName(identity.Namespace, 63) || strings.Contains(identity.Namespace, ".") {
			return "", "", errors.New("namespaced projection resource has an invalid namespace")
		}
		base += "/namespaces/" + identity.Namespace
	} else if identity.Namespace != "" {
		return "", "", errors.New("cluster-scoped projection resource must not declare a namespace")
	}
	collection := base + "/" + route.resource
	return collection, collection + "/" + identity.Name, nil
}

func validName(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`).MatchString(value)
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode projection object: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	return contract.JCS(generic)
}
