package stageauthority

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"gopkg.in/yaml.v3"
)

const (
	RuntimeInstallationPlanFormat = "ok147-bounded-stage-authority-runtime-installation-plan/v1"
	maximumRuntimePackageBytes    = 2 * 1024 * 1024
)

// RuntimePackageFileConfig binds replay of one private package to its exact
// public receipt. Loading is local-only and grants no installation authority.
type RuntimePackageFileConfig struct {
	PackagePath           string
	ReceiptPath           string
	ExpectedReceiptDigest string
}

type RuntimeInstallationCreate struct {
	Order           int    `json:"order"`
	APIVersion      string `json:"apiVersion"`
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	PreflightMethod string `json:"preflightMethod"`
	ObjectPath      string `json:"objectPath"`
	CreateMethod    string `json:"createMethod"`
	CollectionPath  string `json:"collectionPath"`
	ObjectDigest    string `json:"objectDigest"`
}

// RuntimeInstallationPlan is the exact six-object create sequence. It is an
// offline proof and deliberately carries no credential or mutation grant.
type RuntimeInstallationPlan struct {
	Format          string                      `json:"format"`
	State           string                      `json:"state"`
	Authority       string                      `json:"authority"`
	Namespace       string                      `json:"namespace"`
	Name            string                      `json:"name"`
	PackageDigest   string                      `json:"packageDigest"`
	Creates         []RuntimeInstallationCreate `json:"creates"`
	MutationAllowed bool                        `json:"mutationAllowed"`
}

type runtimeInstallObject struct {
	plan RuntimeInstallationCreate
	raw  []byte
}

func LoadRuntimePackage(config RuntimePackageFileConfig) (VerifiedRuntimePackage, error) {
	if !digestPattern.MatchString(config.ExpectedReceiptDigest) {
		return VerifiedRuntimePackage{}, errors.New("bounded stage authority receipt identity is invalid")
	}
	packageRaw, err := readPrivateRegular(config.PackagePath, maximumRuntimePackageBytes, true)
	if err != nil {
		return VerifiedRuntimePackage{}, errors.New("read private bounded stage authority runtime package")
	}
	receiptRaw, err := readPrivateRegular(config.ReceiptPath, maximumPolicyBytes, false)
	if err != nil || digest.SHA256(receiptRaw) != config.ExpectedReceiptDigest {
		return VerifiedRuntimePackage{}, errors.New("bounded stage authority public receipt differs")
	}
	var receipt RuntimePackageReceipt
	if err := jsonstrict.Decode(receiptRaw, &receipt); err != nil {
		return VerifiedRuntimePackage{}, errors.New("decode strict bounded stage authority receipt")
	}
	packaged := VerifiedRuntimePackage{raw: packageRaw, receipt: receipt, verified: true}
	if err := verifyRuntimePackage(packaged); err != nil {
		return VerifiedRuntimePackage{}, errors.New("verify replayed bounded stage authority package")
	}
	return packaged, nil
}

// PlanRuntimeInstallation derives the fixed Secret -> ServiceAccount -> PVC
// -> Service -> NetworkPolicy -> StatefulSet sequence without API contact.
func PlanRuntimeInstallation(packaged VerifiedRuntimePackage, authority string) (RuntimeInstallationPlan, error) {
	plan, _, err := prepareRuntimeInstallation(packaged, authority)
	return plan, err
}

func prepareRuntimeInstallation(packaged VerifiedRuntimePackage, authority string) (RuntimeInstallationPlan, []runtimeInstallObject, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return RuntimeInstallationPlan{}, nil, err
	}
	if authority != "ok-mgmt" {
		return RuntimeInstallationPlan{}, nil, errors.New("bounded stage authority runtime target must be ok-mgmt")
	}
	raw, err := packaged.PrivateBytes()
	if err != nil {
		return RuntimeInstallationPlan{}, nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	values := make([]map[string]any, 0, 6)
	for {
		var value map[string]any
		err := decoder.Decode(&value)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(value) == 0 {
			return RuntimeInstallationPlan{}, nil, errors.New("decode bounded stage authority package")
		}
		values = append(values, value)
	}
	if len(values) != 6 || len(receipt.ObjectKinds) != 6 {
		return RuntimeInstallationPlan{}, nil, errors.New("bounded stage authority package object count differs")
	}
	creates := make([]RuntimeInstallationCreate, 0, 6)
	objects := make([]runtimeInstallObject, 0, 6)
	for index, value := range values {
		apiVersion, _ := value["apiVersion"].(string)
		kind, _ := value["kind"].(string)
		metadata, _ := value["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if kind != receipt.ObjectKinds[index] || namespace != "openkubes-execution-system" || metadata["generateName"] != nil {
			return RuntimeInstallationPlan{}, nil, errors.New("bounded stage authority object identity differs")
		}
		if !expectedRuntimeObjectIdentity(index, kind, name, value, receipt) {
			return RuntimeInstallationPlan{}, nil, errors.New("bounded stage authority object semantics differ")
		}
		collectionPath, objectPath, err := runtimeInstallationPaths(apiVersion, kind, namespace, name)
		if err != nil {
			return RuntimeInstallationPlan{}, nil, err
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			return RuntimeInstallationPlan{}, nil, errors.New("encode bounded stage authority object")
		}
		create := RuntimeInstallationCreate{
			Order: index + 1, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			PreflightMethod: http.MethodGet, ObjectPath: objectPath, CreateMethod: http.MethodPost,
			CollectionPath: collectionPath, ObjectDigest: digest.SHA256(canonical),
		}
		creates = append(creates, create)
		objects = append(objects, runtimeInstallObject{plan: create, raw: canonical})
	}
	return RuntimeInstallationPlan{
		Format: RuntimeInstallationPlanFormat, State: "VERIFIED", Authority: authority,
		Namespace: "openkubes-execution-system", Name: "ok147-stage-authority",
		PackageDigest: receipt.PackageDigest, Creates: creates, MutationAllowed: false,
	}, objects, nil
}

func expectedRuntimeObjectIdentity(index int, kind, name string, value map[string]any, receipt RuntimePackageReceipt) bool {
	expectedNames := []string{"ok147-stage-authority-private", "ok147-stage-authority", "ok147-stage-authority-state", "ok147-stage-authority", "ok147-stage-authority", "ok147-stage-authority"}
	if index < 0 || index >= len(expectedNames) || name != expectedNames[index] {
		return false
	}
	switch kind {
	case "Secret":
		metadata, _ := value["metadata"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		data, _ := value["data"].(map[string]any)
		return value["immutable"] == true && value["type"] == "Opaque" && len(data) == 5 && annotations["openkubes.io/policy-digest"] == receipt.PolicyDigest && annotations["openkubes.io/key-id"] == receipt.KeyID
	case "ServiceAccount":
		return value["automountServiceAccountToken"] == false
	case "PersistentVolumeClaim":
		spec, _ := value["spec"].(map[string]any)
		modes, _ := spec["accessModes"].([]any)
		return len(modes) == 1 && modes[0] == "ReadWriteOnce"
	case "Service":
		spec, _ := value["spec"].(map[string]any)
		selector, _ := spec["selector"].(map[string]any)
		serviceIP, _ := spec["clusterIP"].(string)
		return validRuntimeServiceIP(serviceIP) && digest.SHA256([]byte(serviceIP)) == receipt.ServiceIdentityDigest && selector["app.kubernetes.io/name"] == "ok147-stage-authority"
	case "NetworkPolicy":
		spec, _ := value["spec"].(map[string]any)
		return spec != nil
	case "StatefulSet":
		metadata, _ := value["metadata"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		spec, _ := value["spec"].(map[string]any)
		return spec["replicas"] == 1 && annotations["openkubes.io/policy-digest"] == receipt.PolicyDigest && annotations["openkubes.io/key-id"] == receipt.KeyID
	default:
		return false
	}
}

func runtimeInstallationPaths(apiVersion, kind, namespace, name string) (string, string, error) {
	var collection string
	switch {
	case apiVersion == "v1" && kind == "Secret":
		collection = "/api/v1/namespaces/" + namespace + "/secrets"
	case apiVersion == "v1" && kind == "ServiceAccount":
		collection = "/api/v1/namespaces/" + namespace + "/serviceaccounts"
	case apiVersion == "v1" && kind == "PersistentVolumeClaim":
		collection = "/api/v1/namespaces/" + namespace + "/persistentvolumeclaims"
	case apiVersion == "v1" && kind == "Service":
		collection = "/api/v1/namespaces/" + namespace + "/services"
	case apiVersion == "networking.k8s.io/v1" && kind == "NetworkPolicy":
		collection = "/apis/networking.k8s.io/v1/namespaces/" + namespace + "/networkpolicies"
	case apiVersion == "apps/v1" && kind == "StatefulSet":
		collection = "/apis/apps/v1/namespaces/" + namespace + "/statefulsets"
	default:
		return "", "", errors.New("bounded stage authority object API is unsupported")
	}
	return collection, collection + "/" + name, nil
}
