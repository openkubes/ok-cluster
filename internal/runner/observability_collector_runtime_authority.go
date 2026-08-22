package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sync"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	ObservabilityCollectorRuntimeAuthorityPackageFormat = "ok147-observability-collector-runtime-authority-package/v1"
	ObservabilityCollectorRuntimeAuthorityPlanFormat    = "ok147-observability-collector-runtime-authority-plan/v1"
	ObservabilityCollectorRuntimeAuthorityReceiptFormat = "ok147-observability-collector-runtime-authority-installation-receipt/v1"
	observabilityCollectorRuntimeRole                   = "ok147-observability-collector-runtime"
)

type ObservabilityCollectorRuntimeAuthorityPackageConfig struct {
	Manifest               []byte
	ExpectedManifestDigest string
	TargetIdentityDigest   string
}

type ObservabilityCollectorRuntimeAuthorityPackageReceipt struct {
	Format               string   `json:"format"`
	State                string   `json:"state"`
	PackageDigest        string   `json:"packageDigest"`
	ManifestDigest       string   `json:"manifestDigest"`
	TargetIdentityDigest string   `json:"targetIdentityDigest"`
	ObjectDigests        []string `json:"objectDigests"`
	MutationAllowed      bool     `json:"mutationAllowed"`
}

type VerifiedObservabilityCollectorRuntimeAuthorityPackage struct {
	raw      []byte
	receipt  ObservabilityCollectorRuntimeAuthorityPackageReceipt
	verified bool
}

type ObservabilityCollectorRuntimeAuthorityPlan struct {
	Format               string                      `json:"format"`
	State                string                      `json:"state"`
	PackageDigest        string                      `json:"packageDigest"`
	ManifestDigest       string                      `json:"manifestDigest"`
	TargetIdentityDigest string                      `json:"targetIdentityDigest"`
	Creates              []SubmissionStageCreatePlan `json:"creates"`
	MutationAllowed      bool                        `json:"mutationAllowed"`
}

type ObservabilityCollectorRuntimeAuthorityInstallationReceipt struct {
	Format               string                           `json:"format"`
	PackageDigest        string                           `json:"packageDigest"`
	TargetIdentityDigest string                           `json:"targetIdentityDigest"`
	State                string                           `json:"state"`
	MutationState        string                           `json:"mutationState"`
	Results              []SubmissionStageInstalledObject `json:"results"`
}

type observabilityCollectorRuntimeAuthorityClientConfig struct {
	Endpoint          string
	BearerToken       string
	ClientCertificate bool
	TargetIdentity    string
	Client            *http.Client
}

type KubernetesObservabilityCollectorRuntimeAuthorityInstaller struct {
	mu                sync.Mutex
	used              bool
	endpoint          *url.URL
	token             string
	clientCertificate bool
	client            *http.Client
	plan              ObservabilityCollectorRuntimeAuthorityPlan
	objects           []submissionStageInstallObject
}

// BuildObservabilityCollectorRuntimeAuthorityPackage verifies the exact five
// workload-side objects needed before a short-lived collector installer token
// can exist. It performs no API request and grants no mutation authority.
func BuildObservabilityCollectorRuntimeAuthorityPackage(config ObservabilityCollectorRuntimeAuthorityPackageConfig) (VerifiedObservabilityCollectorRuntimeAuthorityPackage, error) {
	if len(config.Manifest) == 0 || !stageReceiptPrefixDigestPattern.MatchString(config.ExpectedManifestDigest) ||
		digest.SHA256(config.Manifest) != config.ExpectedManifestDigest || !stageReceiptPrefixDigestPattern.MatchString(config.TargetIdentityDigest) {
		return VerifiedObservabilityCollectorRuntimeAuthorityPackage{}, errors.New("collector runtime authority package binding is invalid")
	}
	objects, err := decodeFullRunActivationObjects(config.Manifest, 5)
	if err != nil {
		return VerifiedObservabilityCollectorRuntimeAuthorityPackage{}, errors.New("decode collector runtime authority package")
	}
	if err := verifyObservabilityCollectorRuntimeAuthorityObjects(objects); err != nil {
		return VerifiedObservabilityCollectorRuntimeAuthorityPackage{}, err
	}
	objectDigests := make([]string, 0, len(objects))
	for _, object := range objects {
		raw, err := json.Marshal(object)
		if err != nil {
			return VerifiedObservabilityCollectorRuntimeAuthorityPackage{}, errors.New("encode collector runtime authority object")
		}
		objectDigests = append(objectDigests, digest.SHA256(raw))
	}
	return VerifiedObservabilityCollectorRuntimeAuthorityPackage{
		raw: append([]byte(nil), config.Manifest...), verified: true,
		receipt: ObservabilityCollectorRuntimeAuthorityPackageReceipt{
			Format: ObservabilityCollectorRuntimeAuthorityPackageFormat, State: "VERIFIED",
			PackageDigest: digest.SHA256(config.Manifest), ManifestDigest: config.ExpectedManifestDigest,
			TargetIdentityDigest: config.TargetIdentityDigest, ObjectDigests: objectDigests, MutationAllowed: false,
		},
	}, nil
}

func (packaged VerifiedObservabilityCollectorRuntimeAuthorityPackage) Receipt() (ObservabilityCollectorRuntimeAuthorityPackageReceipt, error) {
	if err := verifyObservabilityCollectorRuntimeAuthorityPackage(packaged); err != nil {
		return ObservabilityCollectorRuntimeAuthorityPackageReceipt{}, err
	}
	receipt := packaged.receipt
	receipt.ObjectDigests = append([]string(nil), receipt.ObjectDigests...)
	return receipt, nil
}

func verifyObservabilityCollectorRuntimeAuthorityPackage(packaged VerifiedObservabilityCollectorRuntimeAuthorityPackage) error {
	if !packaged.verified || packaged.receipt.Format != ObservabilityCollectorRuntimeAuthorityPackageFormat || packaged.receipt.State != "VERIFIED" ||
		packaged.receipt.MutationAllowed || len(packaged.raw) == 0 || len(packaged.receipt.ObjectDigests) != 5 ||
		digest.SHA256(packaged.raw) != packaged.receipt.PackageDigest || packaged.receipt.ManifestDigest != packaged.receipt.PackageDigest ||
		!stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.TargetIdentityDigest) {
		return errors.New("collector runtime authority package was not produced by verification")
	}
	objects, err := decodeFullRunActivationObjects(packaged.raw, 5)
	if err != nil || verifyObservabilityCollectorRuntimeAuthorityObjects(objects) != nil {
		return errors.New("collector runtime authority package changed after verification")
	}
	for index, object := range objects {
		raw, err := json.Marshal(object)
		if err != nil || digest.SHA256(raw) != packaged.receipt.ObjectDigests[index] {
			return errors.New("collector runtime authority object identity changed after verification")
		}
	}
	return nil
}

func PlanObservabilityCollectorRuntimeAuthorityInstallation(packaged VerifiedObservabilityCollectorRuntimeAuthorityPackage) (ObservabilityCollectorRuntimeAuthorityPlan, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return ObservabilityCollectorRuntimeAuthorityPlan{}, err
	}
	objects, err := decodeFullRunActivationObjects(packaged.raw, 5)
	if err != nil {
		return ObservabilityCollectorRuntimeAuthorityPlan{}, err
	}
	creates := make([]SubmissionStageCreatePlan, 0, 4)
	for index, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		metadata, _ := object["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		collection, objectPath, err := observabilityCollectorRuntimeAuthorityPaths(apiVersion, kind, namespace, name)
		if err != nil {
			return ObservabilityCollectorRuntimeAuthorityPlan{}, err
		}
		raw, err := json.Marshal(object)
		if err != nil || digest.SHA256(raw) != receipt.ObjectDigests[index] {
			return ObservabilityCollectorRuntimeAuthorityPlan{}, errors.New("collector runtime authority plan object differs")
		}
		creates = append(creates, SubmissionStageCreatePlan{
			Order: index + 1, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			PreflightMethod: http.MethodGet, ObjectPath: objectPath, CreateMethod: http.MethodPost,
			CollectionPath: collection, ObjectDigest: receipt.ObjectDigests[index],
		})
	}
	return ObservabilityCollectorRuntimeAuthorityPlan{
		Format: ObservabilityCollectorRuntimeAuthorityPlanFormat, State: "VERIFIED",
		PackageDigest: receipt.PackageDigest, ManifestDigest: receipt.ManifestDigest,
		TargetIdentityDigest: receipt.TargetIdentityDigest, Creates: creates, MutationAllowed: false,
	}, nil
}

func OpenKubernetesObservabilityCollectorRuntimeAuthorityInstaller(workload WorkloadAuthorityFileResolverConfig, packaged VerifiedObservabilityCollectorRuntimeAuthorityPackage) (*KubernetesObservabilityCollectorRuntimeAuthorityInstaller, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return nil, err
	}
	binding, authority, err := loadWorkloadAuthorityFiles(workload)
	if err != nil || digest.SHA256([]byte(binding.TargetClusterUID)) != receipt.TargetIdentityDigest {
		return nil, errors.New("collector runtime authority installer differs from workload target")
	}
	transport, err := openBoundedKubernetesAuthorityTransport(authority)
	if err != nil || digest.SHA256(transport.caData) != authority.CABundleDigest {
		return nil, errors.New("open collector runtime authority workload credential")
	}
	return newKubernetesObservabilityCollectorRuntimeAuthorityInstaller(observabilityCollectorRuntimeAuthorityClientConfig{
		Endpoint: authority.Endpoint, BearerToken: transport.bearerToken, ClientCertificate: transport.clientCertificate,
		TargetIdentity: receipt.TargetIdentityDigest, Client: transport.client,
	}, packaged)
}

func newKubernetesObservabilityCollectorRuntimeAuthorityInstaller(config observabilityCollectorRuntimeAuthorityClientConfig, packaged VerifiedObservabilityCollectorRuntimeAuthorityPackage) (*KubernetesObservabilityCollectorRuntimeAuthorityInstaller, error) {
	plan, objects, err := prepareObservabilityCollectorRuntimeAuthorityInstallation(packaged)
	if err != nil || config.TargetIdentity != plan.TargetIdentityDigest {
		return nil, errors.New("collector runtime authority installer target differs")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Endpoint)
	if err != nil || config.Client == nil || (config.BearerToken != "") == config.ClientCertificate {
		return nil, errors.New("collector runtime authority installer credential is invalid")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("parse collector runtime authority endpoint")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &KubernetesObservabilityCollectorRuntimeAuthorityInstaller{
		endpoint: parsed, token: config.BearerToken, clientCertificate: config.ClientCertificate,
		client: &client, plan: plan, objects: objects,
	}, nil
}

func (installer *KubernetesObservabilityCollectorRuntimeAuthorityInstaller) Install(ctx context.Context) (ObservabilityCollectorRuntimeAuthorityInstallationReceipt, error) {
	receipt := installer.newReceipt()
	if installer == nil || installer.client == nil {
		return receipt, errors.New("collector runtime authority installer is required")
	}
	installer.mu.Lock()
	if installer.used {
		installer.mu.Unlock()
		return stopObservabilityCollectorRuntimeAuthority(receipt, "STOPPED_ZERO_WRITE", errors.New("collector runtime authority installer is single-use"))
	}
	installer.used = true
	installer.mu.Unlock()
	for _, object := range installer.objects {
		_, status, err := installer.request(ctx, http.MethodGet, object.plan.ObjectPath, nil)
		if err != nil || status != http.StatusNotFound {
			if err == nil {
				err = fmt.Errorf("collector runtime authority preflight returned HTTP %d", status)
			}
			return stopObservabilityCollectorRuntimeAuthority(receipt, "STOPPED_ZERO_WRITE", err)
		}
	}
	receipt.State = "INSTALLING"
	for _, object := range installer.objects {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		raw, status, err := installer.request(ctx, http.MethodPost, object.plan.CollectionPath, object.raw)
		if err != nil || status != http.StatusCreated {
			if err == nil {
				err = fmt.Errorf("collector runtime authority create returned HTTP %d", status)
			}
			return stopObservabilityCollectorRuntimeAuthority(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		uid, resourceVersion, err := verifySubmissionStageCreatedObject(raw, object)
		if err != nil {
			return stopObservabilityCollectorRuntimeAuthority(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", errors.New("created collector runtime authority object differs"))
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, SubmissionStageInstalledObject{
			Order: object.plan.Order, APIVersion: object.plan.APIVersion, Kind: object.plan.Kind,
			Namespace: object.plan.Namespace, Name: object.plan.Name, ObjectDigest: object.plan.ObjectDigest,
			UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)), State: "CREATED",
		})
	}
	receipt.State = "INSTALLED"
	return receipt, nil
}

func (installer *KubernetesObservabilityCollectorRuntimeAuthorityInstaller) newReceipt() ObservabilityCollectorRuntimeAuthorityInstallationReceipt {
	receipt := ObservabilityCollectorRuntimeAuthorityInstallationReceipt{
		Format: ObservabilityCollectorRuntimeAuthorityReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED",
		Results: []SubmissionStageInstalledObject{},
	}
	if installer != nil {
		receipt.PackageDigest = installer.plan.PackageDigest
		receipt.TargetIdentityDigest = installer.plan.TargetIdentityDigest
	}
	return receipt
}

func stopObservabilityCollectorRuntimeAuthority(receipt ObservabilityCollectorRuntimeAuthorityInstallationReceipt, state string, err error) (ObservabilityCollectorRuntimeAuthorityInstallationReceipt, error) {
	receipt.State = state
	return receipt, err
}

func (installer *KubernetesObservabilityCollectorRuntimeAuthorityInstaller) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *installer.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct collector runtime authority request")
	}
	request.Header.Set("Accept", "application/json")
	if !installer.clientCertificate {
		request.Header.Set("Authorization", "Bearer "+installer.token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := installer.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("collector runtime authority %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("collector runtime authority response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("collector runtime authority response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func prepareObservabilityCollectorRuntimeAuthorityInstallation(packaged VerifiedObservabilityCollectorRuntimeAuthorityPackage) (ObservabilityCollectorRuntimeAuthorityPlan, []submissionStageInstallObject, error) {
	plan, err := PlanObservabilityCollectorRuntimeAuthorityInstallation(packaged)
	if err != nil {
		return ObservabilityCollectorRuntimeAuthorityPlan{}, nil, err
	}
	values, err := decodeFullRunActivationObjects(packaged.raw, 5)
	if err != nil {
		return ObservabilityCollectorRuntimeAuthorityPlan{}, nil, err
	}
	objects := make([]submissionStageInstallObject, 0, 5)
	for index, value := range values {
		raw, err := json.Marshal(value)
		if err != nil || digest.SHA256(raw) != plan.Creates[index].ObjectDigest {
			return ObservabilityCollectorRuntimeAuthorityPlan{}, nil, errors.New("collector runtime authority object differs from plan")
		}
		objects = append(objects, submissionStageInstallObject{plan: plan.Creates[index], raw: raw})
	}
	return plan, objects, nil
}

func observabilityCollectorRuntimeAuthorityPaths(apiVersion, kind, namespace, name string) (string, string, error) {
	var collection string
	switch {
	case apiVersion == "v1" && kind == "Namespace" && namespace == "":
		collection = "/api/v1/namespaces"
	case apiVersion == "v1" && kind == "ServiceAccount":
		collection = "/api/v1/namespaces/" + namespace + "/serviceaccounts"
	case apiVersion == "rbac.authorization.k8s.io/v1" && kind == "Role":
		collection = "/apis/rbac.authorization.k8s.io/v1/namespaces/" + namespace + "/roles"
	case apiVersion == "rbac.authorization.k8s.io/v1" && kind == "RoleBinding":
		collection = "/apis/rbac.authorization.k8s.io/v1/namespaces/" + namespace + "/rolebindings"
	default:
		return "", "", errors.New("collector runtime authority object kind is invalid")
	}
	return collection, collection + "/" + name, nil
}

func verifyObservabilityCollectorRuntimeAuthorityObjects(objects []map[string]any) error {
	if len(objects) != 5 {
		return errors.New("collector runtime authority requires exactly five objects")
	}
	want := []struct{ apiVersion, kind, namespace, name string }{
		{"v1", "Namespace", "", observabilityCollectorInstallerNamespace},
		{"v1", "ServiceAccount", observabilityCollectorInstallerNamespace, observabilityCollectorRuntimeServiceAccount},
		{"v1", "ServiceAccount", observabilityCollectorInstallerNamespace, observabilityCollectorInstallerServiceAccount},
		{"rbac.authorization.k8s.io/v1", "Role", observabilityCollectorInstallerNamespace, observabilityCollectorRuntimeRole},
		{"rbac.authorization.k8s.io/v1", "RoleBinding", observabilityCollectorInstallerNamespace, observabilityCollectorRuntimeRole},
	}
	for index, expected := range want {
		metadata, ok := objects[index]["metadata"].(map[string]any)
		if !ok || objects[index]["apiVersion"] != expected.apiVersion || objects[index]["kind"] != expected.kind ||
			metadata["name"] != expected.name || textValue(metadata["namespace"]) != expected.namespace {
			return errors.New("collector runtime authority object identity or labels differ")
		}
		for _, forbidden := range []string{"generateName", "uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "managedFields", "ownerReferences", "finalizers"} {
			if _, exists := metadata[forbidden]; exists {
				return errors.New("collector runtime authority contains runtime metadata")
			}
		}
	}
	if !exactCollectorRuntimeAuthorityLabels(objects[0]["metadata"].(map[string]any)["labels"], "independent-evidence", true) ||
		!exactCollectorRuntimeAuthorityLabels(objects[1]["metadata"].(map[string]any)["labels"], "submission-stage", false) ||
		!exactCollectorRuntimeAuthorityLabels(objects[2]["metadata"].(map[string]any)["labels"], "independent-evidence-installer", false) ||
		!exactCollectorRuntimeAuthorityLabels(objects[3]["metadata"].(map[string]any)["labels"], "independent-evidence", false) ||
		!exactCollectorRuntimeAuthorityLabels(objects[4]["metadata"].(map[string]any)["labels"], "independent-evidence", false) {
		return errors.New("collector runtime authority object labels differ")
	}
	if !exactStringMapKeys(objects[0], "apiVersion", "kind", "metadata") {
		return errors.New("collector runtime authority Namespace shape differs")
	}
	namespaceLabels := objects[0]["metadata"].(map[string]any)["labels"].(map[string]any)
	for _, key := range []string{"pod-security.kubernetes.io/enforce", "pod-security.kubernetes.io/audit", "pod-security.kubernetes.io/warn"} {
		if namespaceLabels[key] != "restricted" {
			return errors.New("collector runtime authority Namespace is not restricted")
		}
	}
	if !exactStringMapKeys(objects[1], "apiVersion", "kind", "metadata", "automountServiceAccountToken") || objects[1]["automountServiceAccountToken"] != false {
		return errors.New("collector runtime authority ServiceAccount shape differs")
	}
	if !exactStringMapKeys(objects[2], "apiVersion", "kind", "metadata", "automountServiceAccountToken") || objects[2]["automountServiceAccountToken"] != false {
		return errors.New("collector runtime authority installer ServiceAccount shape differs")
	}
	if !exactStringMapKeys(objects[3], "apiVersion", "kind", "metadata", "rules") || !exactCollectorRuntimeAuthorityRules(objects[3]["rules"]) {
		return errors.New("collector runtime authority Role exceeds exact permissions")
	}
	if !exactStringMapKeys(objects[4], "apiVersion", "kind", "metadata", "roleRef", "subjects") || !exactCollectorRuntimeAuthorityBinding(objects[4]) {
		return errors.New("collector runtime authority RoleBinding differs")
	}
	return nil
}

func exactCollectorRuntimeAuthorityLabels(raw any, boundary string, namespace bool) bool {
	labels, ok := raw.(map[string]any)
	if !ok || labels["openkubes.io/runtime-boundary"] != boundary {
		return false
	}
	if namespace {
		return len(labels) == 4
	}
	return len(labels) == 2 && labels["app.kubernetes.io/name"] == "ok-cluster-contract-executor"
}

func exactCollectorRuntimeAuthorityRules(raw any) bool {
	rules, ok := raw.([]any)
	if !ok || len(rules) != 4 {
		return false
	}
	want := []struct {
		apiGroups, resources, resourceNames, verbs []string
	}{
		{[]string{""}, []string{"serviceaccounts"}, []string{observabilityCollectorRuntimeServiceAccount}, []string{"get"}},
		{[]string{""}, []string{"secrets", "services"}, nil, []string{"get", "create"}},
		{[]string{"networking.k8s.io"}, []string{"networkpolicies"}, nil, []string{"get", "create"}},
		{[]string{"batch"}, []string{"jobs"}, nil, []string{"get", "create"}},
	}
	for index, expected := range want {
		rule, ok := rules[index].(map[string]any)
		if !ok || !exactStringList(rule["apiGroups"], expected.apiGroups) || !exactStringList(rule["resources"], expected.resources) || !exactStringList(rule["verbs"], expected.verbs) {
			return false
		}
		if expected.resourceNames == nil {
			if len(rule) != 3 {
				return false
			}
		} else if len(rule) != 4 || !exactStringList(rule["resourceNames"], expected.resourceNames) {
			return false
		}
	}
	return true
}

func exactCollectorRuntimeAuthorityBinding(object map[string]any) bool {
	roleRef, ok := object["roleRef"].(map[string]any)
	if !ok || !exactStringMapKeys(roleRef, "apiGroup", "kind", "name") || roleRef["apiGroup"] != "rbac.authorization.k8s.io" || roleRef["kind"] != "Role" || roleRef["name"] != observabilityCollectorRuntimeRole {
		return false
	}
	subjects, ok := object["subjects"].([]any)
	if !ok || len(subjects) != 1 {
		return false
	}
	subject, ok := subjects[0].(map[string]any)
	return ok && exactStringMapKeys(subject, "kind", "name", "namespace") && subject["kind"] == "ServiceAccount" &&
		subject["name"] == observabilityCollectorInstallerServiceAccount && subject["namespace"] == observabilityCollectorInstallerNamespace
}

func exactStringMapKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, exists := value[key]; !exists {
			return false
		}
	}
	return true
}

func exactStringList(raw any, expected []string) bool {
	values, ok := raw.([]any)
	if !ok || len(values) != len(expected) {
		return false
	}
	for index := range expected {
		if values[index] != expected[index] {
			return false
		}
	}
	return true
}
