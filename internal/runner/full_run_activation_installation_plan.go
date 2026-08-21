package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

const FullRunExecutionActivationInstallationPlanFormat = "ok147-full-run-execution-activation-installation-plan/v3"

type FullRunExecutionActivationPrerequisite struct {
	Order       int    `json:"order"`
	APIVersion  string `json:"apiVersion"`
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name"`
	Method      string `json:"method"`
	ObjectPath  string `json:"objectPath"`
	ExpectState string `json:"expectState"`
}

// FullRunExecutionActivationInstallationPlan is the credential-free exact
// absence/create sequence for the complete ephemeral Stage 1-12 execution.
// It is evidence and grants no installation authority.
type FullRunExecutionActivationInstallationPlan struct {
	Format          string                                   `json:"format"`
	State           string                                   `json:"state"`
	RunID           string                                   `json:"runId"`
	PackageDigest   string                                   `json:"packageDigest"`
	PlanDigest      string                                   `json:"planDigest"`
	Authority       string                                   `json:"authority"`
	Prerequisites   []FullRunExecutionActivationPrerequisite `json:"prerequisites"`
	Creates         []SubmissionStageCreatePlan              `json:"creates"`
	MutationAllowed bool                                     `json:"mutationAllowed"`
}

// PlanFullRunExecutionActivationInstallation derives the exact
// executor-Secret -> evidence-Secret -> NetworkPolicy -> Job sequence without
// opening a credential or contacting Kubernetes.
func PlanFullRunExecutionActivationInstallation(packaged VerifiedFullRunExecutionActivationPackage) (FullRunExecutionActivationInstallationPlan, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return FullRunExecutionActivationInstallationPlan{}, err
	}
	expectedKinds := []string{"Secret", "Secret", "NetworkPolicy", "Job"}
	if !equalStringList(receipt.ObjectKinds, expectedKinds) || packaged.managementAuthority == "" {
		return FullRunExecutionActivationInstallationPlan{}, errors.New("full-run activation package inventory or authority is invalid")
	}
	objects, err := decodeFullRunActivationObjects(packaged.raw, len(expectedKinds))
	if err != nil {
		return FullRunExecutionActivationInstallationPlan{}, err
	}

	runID := ""
	creates := make([]SubmissionStageCreatePlan, 0, len(objects))
	for index, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		if kind != expectedKinds[index] {
			return FullRunExecutionActivationInstallationPlan{}, errors.New("full-run activation create order is invalid")
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return FullRunExecutionActivationInstallationPlan{}, errors.New("full-run activation object metadata is invalid")
		}
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || namespace != submissionStageInputNamespace || metadata["generateName"] != nil {
			return FullRunExecutionActivationInstallationPlan{}, errors.New("full-run activation object identity is invalid")
		}
		collectionPath, objectPath, err := postRuntimeActivationCreatePaths(apiVersion, kind, namespace, name)
		if err != nil {
			return FullRunExecutionActivationInstallationPlan{}, err
		}
		canonical, err := json.Marshal(object)
		if err != nil {
			return FullRunExecutionActivationInstallationPlan{}, errors.New("encode full-run activation object")
		}
		creates = append(creates, SubmissionStageCreatePlan{
			Order: index + 1, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			PreflightMethod: http.MethodGet, ObjectPath: objectPath, CreateMethod: http.MethodPost,
			CollectionPath: collectionPath, ObjectDigest: digest.SHA256(canonical),
		})
		switch index {
		case 0:
			if !fullRunActivationSecretMatches(object, receipt.ActivationSecret, "full-run", receipt.BundleDigest, receipt.ManifestDigest, "", len(fullRunExecutionBundleFiles)+1) {
				return FullRunExecutionActivationInstallationPlan{}, errors.New("full-run executor Secret semantics differ")
			}
		case 1:
			if !fullRunActivationSecretMatches(object, receipt.EvidenceAuthoritySecret, "independent-evidence", "", receipt.SourceManifestDigest, receipt.EvidenceActivationDigest, 4) {
				return FullRunExecutionActivationInstallationPlan{}, errors.New("full-run Evidence Authority Secret semantics differ")
			}
		case 2:
			runID = name
			spec, _ := object["spec"].(map[string]any)
			selector, _ := spec["podSelector"].(map[string]any)
			matchLabels, _ := selector["matchLabels"].(map[string]any)
			if matchLabels["openkubes.io/execution-id"] != runID {
				return FullRunExecutionActivationInstallationPlan{}, errors.New("full-run NetworkPolicy selector differs")
			}
		case 3:
			spec, _ := object["spec"].(map[string]any)
			template, _ := spec["template"].(map[string]any)
			podSpec, _ := template["spec"].(map[string]any)
			annotations, _ := metadata["annotations"].(map[string]any)
			if name != runID || spec["backoffLimit"] != 0 || podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" ||
				podSpec["automountServiceAccountToken"] != false || annotations["openkubes.io/bundle-digest"] != receipt.BundleDigest ||
				annotations["openkubes.io/manifest-digest"] != receipt.ManifestDigest ||
				annotations["openkubes.io/evidence-activation-digest"] != receipt.EvidenceActivationDigest ||
				annotations["openkubes.io/evidence-key-id"] != receipt.EvidenceKeyID ||
				!fullRunJobMountsPrivateSecrets(podSpec, receipt.ActivationSecret, receipt.EvidenceAuthoritySecret) {
				return FullRunExecutionActivationInstallationPlan{}, errors.New("full-run activation Job binding differs")
			}
		}
	}
	return FullRunExecutionActivationInstallationPlan{
		Format: FullRunExecutionActivationInstallationPlanFormat, State: "VERIFIED", RunID: runID,
		PackageDigest: receipt.PackageDigest, PlanDigest: receipt.PlanDigest,
		Authority: packaged.managementAuthority,
		Prerequisites: []FullRunExecutionActivationPrerequisite{
			{Order: 1, APIVersion: "v1", Kind: "Namespace", Name: submissionStageInputNamespace, Method: http.MethodGet,
				ObjectPath: "/api/v1/namespaces/" + submissionStageInputNamespace, ExpectState: "PRESENT"},
			{Order: 2, APIVersion: "v1", Kind: "ServiceAccount", Namespace: submissionStageInputNamespace, Name: "ok147-contract-executor-runtime", Method: http.MethodGet,
				ObjectPath: "/api/v1/namespaces/" + submissionStageInputNamespace + "/serviceaccounts/ok147-contract-executor-runtime", ExpectState: "PRESENT_EXACT_RUNTIME"},
			{Order: 3, APIVersion: "v1", Kind: "ServiceAccount", Namespace: submissionStageInputNamespace, Name: "ok147-contract-executor", Method: http.MethodGet,
				ObjectPath: "/api/v1/namespaces/" + submissionStageInputNamespace + "/serviceaccounts/ok147-contract-executor", ExpectState: "PRESENT_EXACT_LEDGER_WRITER"},
			{Order: 4, APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: submissionStageInputNamespace, Name: "ok147-ledger-writer", Method: http.MethodGet,
				ObjectPath: "/apis/rbac.authorization.k8s.io/v1/namespaces/" + submissionStageInputNamespace + "/roles/ok147-ledger-writer", ExpectState: "PRESENT_EXACT_LEDGER_WRITER_ROLE"},
			{Order: 5, APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: submissionStageInputNamespace, Name: "ok147-ledger-writer", Method: http.MethodGet,
				ObjectPath: "/apis/rbac.authorization.k8s.io/v1/namespaces/" + submissionStageInputNamespace + "/rolebindings/ok147-ledger-writer", ExpectState: "PRESENT_EXACT_LEDGER_WRITER_BINDING"},
			{Order: 6, APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy", Name: "ok147-contract-executor-ledger", Method: http.MethodGet,
				ObjectPath: "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/ok147-contract-executor-ledger", ExpectState: "PRESENT_EXACT_LEDGER_POLICY"},
			{Order: 7, APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding", Name: "ok147-contract-executor-ledger", Method: http.MethodGet,
				ObjectPath: "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/ok147-contract-executor-ledger", ExpectState: "PRESENT_EXACT_LEDGER_POLICY_BINDING"},
		},
		Creates: creates, MutationAllowed: false,
	}, nil
}

func fullRunActivationSecretMatches(object map[string]any, name, stageID, bundleDigest, manifestDigest, activationDigest string, fileCount int) bool {
	metadata, _ := object["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	binaryData, _ := object["binaryData"].(map[string]any)
	if metadata["name"] != name || object["immutable"] != true || object["type"] != "Opaque" ||
		labels["openkubes.io/stage-id"] != stageID || annotations["openkubes.io/manifest-digest"] != manifestDigest || len(binaryData) != fileCount {
		return false
	}
	if bundleDigest != "" && annotations["openkubes.io/bundle-digest"] != bundleDigest {
		return false
	}
	return activationDigest == "" || annotations["openkubes.io/activation-digest"] == activationDigest
}

func fullRunJobMountsPrivateSecrets(podSpec map[string]any, executorSecret, evidenceSecret string) bool {
	volumes, ok := podSpec["volumes"].([]any)
	if !ok {
		return false
	}
	wanted := map[string]struct {
		secret string
		items  int
	}{
		"activation-source": {secret: executorSecret, items: len(fullRunExecutionBundleFiles) + 1},
		"evidence-source":   {secret: evidenceSecret, items: 4},
	}
	found := map[string]bool{}
	for _, value := range volumes {
		volume, _ := value.(map[string]any)
		name, _ := volume["name"].(string)
		expected, required := wanted[name]
		if !required {
			continue
		}
		secret, _ := volume["secret"].(map[string]any)
		items, _ := secret["items"].([]any)
		if secret["secretName"] != expected.secret || len(items) != expected.items || found[name] {
			return false
		}
		found[name] = true
	}
	return found["activation-source"] && found["evidence-source"]
}

func decodeFullRunActivationObjects(raw []byte, expected int) ([]map[string]any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	objects := make([]map[string]any, 0, expected)
	for {
		var object map[string]any
		err := decoder.Decode(&object)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(object) == 0 {
			return nil, errors.New("decode full-run activation package")
		}
		objects = append(objects, object)
	}
	if len(objects) != expected {
		return nil, errors.New("full-run activation package object count is invalid")
	}
	return objects, nil
}

func prepareFullRunExecutionActivationInstallation(packaged VerifiedFullRunExecutionActivationPackage) (FullRunExecutionActivationInstallationPlan, []submissionStageInstallObject, error) {
	plan, err := PlanFullRunExecutionActivationInstallation(packaged)
	if err != nil {
		return FullRunExecutionActivationInstallationPlan{}, nil, err
	}
	values, err := decodeFullRunActivationObjects(packaged.raw, len(plan.Creates))
	if err != nil {
		return FullRunExecutionActivationInstallationPlan{}, nil, err
	}
	objects := make([]submissionStageInstallObject, 0, len(values))
	for index, value := range values {
		raw, err := json.Marshal(value)
		if err != nil || digest.SHA256(raw) != plan.Creates[index].ObjectDigest {
			return FullRunExecutionActivationInstallationPlan{}, nil, errors.New("full-run activation object differs from plan")
		}
		objects = append(objects, submissionStageInstallObject{plan: plan.Creates[index], raw: raw})
	}
	return plan, objects, nil
}
