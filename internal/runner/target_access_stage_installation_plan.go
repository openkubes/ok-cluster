package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

const TargetAccessStageInstallationPlanFormat = "ok147-target-access-stage-installation-plan/v1"

// TargetAccessStageInstallationPlan is a tokenless offline description of
// the three exact execution-plane objects. It grants no create authority.
type TargetAccessStageInstallationPlan struct {
	Format             string                      `json:"format"`
	State              string                      `json:"state"`
	StageID            string                      `json:"stageId"`
	StagePackageDigest string                      `json:"stagePackageDigest"`
	Authority          string                      `json:"authority"`
	Creates            []SubmissionStageCreatePlan `json:"creates"`
	MutationAllowed    bool                        `json:"mutationAllowed"`
}

// PlanTargetAccessStageInstallation re-verifies the immutable input,
// NetworkPolicy and Job and derives their exact create order without opening
// either credential Secret or contacting Kubernetes.
func PlanTargetAccessStageInstallation(packaged VerifiedTargetAccessStagePackage) (TargetAccessStageInstallationPlan, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return TargetAccessStageInstallationPlan{}, err
	}
	expectedKinds := []string{"ConfigMap", "NetworkPolicy", "Job"}
	if !equalStringList(receipt.ObjectKinds, expectedKinds) {
		return TargetAccessStageInstallationPlan{}, errors.New("target-access package object inventory is invalid")
	}
	documents := bytes.Split(packaged.raw, []byte("\n---\n"))
	if len(documents) != len(expectedKinds) || digest.SHA256(documents[0]) != receipt.InputConfigMapDigest || digest.SHA256(bytes.Join(documents[1:], []byte("\n---\n"))) != receipt.JobEnvelopeDigest {
		return TargetAccessStageInstallationPlan{}, errors.New("target-access package component identity differs")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(packaged.raw))
	objects := make([]map[string]any, 0, len(expectedKinds))
	for {
		var object map[string]any
		err := decoder.Decode(&object)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(object) == 0 {
			return TargetAccessStageInstallationPlan{}, errors.New("decode target-access package")
		}
		objects = append(objects, object)
	}
	if len(objects) != len(expectedKinds) {
		return TargetAccessStageInstallationPlan{}, errors.New("target-access package object count is invalid")
	}

	configMapName, runID := "", ""
	creates := make([]SubmissionStageCreatePlan, 0, len(objects))
	for index, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		if kind != expectedKinds[index] {
			return TargetAccessStageInstallationPlan{}, errors.New("target-access package create order is invalid")
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return TargetAccessStageInstallationPlan{}, errors.New("target-access package object metadata is invalid")
		}
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || namespace != submissionStageInputNamespace || metadata["generateName"] != nil {
			return TargetAccessStageInstallationPlan{}, errors.New("target-access package object identity is invalid")
		}
		collectionPath, objectPath, err := submissionStageCreatePaths(apiVersion, kind, namespace, name)
		if err != nil {
			return TargetAccessStageInstallationPlan{}, err
		}
		canonical, err := json.Marshal(object)
		if err != nil {
			return TargetAccessStageInstallationPlan{}, errors.New("encode target-access package object")
		}
		creates = append(creates, SubmissionStageCreatePlan{
			Order: index + 1, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			PreflightMethod: "GET", ObjectPath: objectPath, CreateMethod: "POST", CollectionPath: collectionPath,
			ObjectDigest: digest.SHA256(canonical),
		})
		switch kind {
		case "ConfigMap":
			labels, _ := metadata["labels"].(map[string]any)
			annotations, _ := metadata["annotations"].(map[string]any)
			if object["immutable"] != true || labels["openkubes.io/stage-id"] != receipt.StageID || annotations["openkubes.io/target-identity-digest"] != receipt.TargetIdentityDigest {
				return TargetAccessStageInstallationPlan{}, errors.New("target-access input ConfigMap semantics differ")
			}
			configMapName = name
		case "NetworkPolicy":
			runID = name
			spec, _ := object["spec"].(map[string]any)
			selector, _ := spec["podSelector"].(map[string]any)
			matchLabels, _ := selector["matchLabels"].(map[string]any)
			if matchLabels["openkubes.io/execution-id"] != runID || lenArrayValue(spec["ingress"]) != 0 || lenArrayValue(spec["egress"]) != 2 {
				return TargetAccessStageInstallationPlan{}, errors.New("target-access NetworkPolicy boundary differs")
			}
		case "Job":
			if name != runID {
				return TargetAccessStageInstallationPlan{}, errors.New("target-access Job and NetworkPolicy identities differ")
			}
			spec, _ := object["spec"].(map[string]any)
			template, _ := spec["template"].(map[string]any)
			podSpec, _ := template["spec"].(map[string]any)
			if podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" || podSpec["automountServiceAccountToken"] != false {
				return TargetAccessStageInstallationPlan{}, errors.New("target-access Job runtime identity is invalid")
			}
			if !jobMountsInputConfigMap(podSpec, configMapName) || !jobUsesTargetAccessCredentialSecrets(podSpec, packaged.ledgerCredential, packaged.workloadCredential) {
				return TargetAccessStageInstallationPlan{}, errors.New("target-access Job binding differs from verified package")
			}
		}
	}
	return TargetAccessStageInstallationPlan{
		Format: TargetAccessStageInstallationPlanFormat, State: "VERIFIED", StageID: receipt.StageID,
		StagePackageDigest: receipt.PackageDigest, Authority: packaged.workloadAuthority,
		Creates: creates, MutationAllowed: false,
	}, nil
}

func jobUsesTargetAccessCredentialSecrets(podSpec map[string]any, ledger, workload string) bool {
	volumes, ok := podSpec["volumes"].([]any)
	if !ok {
		return false
	}
	want := map[string]struct {
		secret string
		items  map[string]string
	}{
		"ledger-credential":   {secret: ledger, items: map[string]string{"token": "token", "ca.crt": "ca.crt"}},
		"workload-credential": {secret: workload, items: map[string]string{"token": "token", "ca.crt": "ca.crt", "binding.json": "binding.json"}},
	}
	found := map[string]bool{}
	for _, item := range volumes {
		volume, _ := item.(map[string]any)
		name, _ := volume["name"].(string)
		expected, relevant := want[name]
		if !relevant {
			continue
		}
		secret, _ := volume["secret"].(map[string]any)
		secretName, _ := secret["secretName"].(string)
		items, _ := secret["items"].([]any)
		if secretName != expected.secret || !exactCredentialSecretItems(items, expected.items) {
			return false
		}
		found[name] = true
	}
	return len(found) == len(want)
}

func lenArrayValue(value any) int {
	items, ok := value.([]any)
	if !ok {
		return -1
	}
	return len(items)
}
