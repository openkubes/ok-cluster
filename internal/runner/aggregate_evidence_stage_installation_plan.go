package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

const AggregateEvidenceStageInstallationPlanFormat = "ok147-aggregate-evidence-stage-installation-plan/v1"

// AggregateEvidenceStageInstallationPlan is a tokenless offline description
// of the three exact public objects. It grants no create authority.
type AggregateEvidenceStageInstallationPlan struct {
	Format                string                      `json:"format"`
	State                 string                      `json:"state"`
	StageID               string                      `json:"stageId"`
	EvidencePackageDigest string                      `json:"evidencePackageDigest"`
	Authority             string                      `json:"authority"`
	Creates               []SubmissionStageCreatePlan `json:"creates"`
	MutationAllowed       bool                        `json:"mutationAllowed"`
}

// PlanAggregateEvidenceStageInstallation verifies the immutable input,
// NetworkPolicy and Job and derives their exact create order without opening
// credentials or contacting Kubernetes.
func PlanAggregateEvidenceStageInstallation(packaged VerifiedAggregateEvidenceStagePackage) (AggregateEvidenceStageInstallationPlan, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return AggregateEvidenceStageInstallationPlan{}, err
	}
	expectedKinds := []string{"ConfigMap", "NetworkPolicy", "Job"}
	if !equalStringList(receipt.ObjectKinds, expectedKinds) {
		return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence package object inventory is invalid")
	}
	documents := bytes.Split(packaged.raw, []byte("\n---\n"))
	if len(documents) != len(expectedKinds) || digest.SHA256(documents[0]) != receipt.InputConfigMapDigest || digest.SHA256(bytes.Join(documents[1:], []byte("\n---\n"))) != receipt.JobEnvelopeDigest {
		return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence package component identity differs")
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
			return AggregateEvidenceStageInstallationPlan{}, errors.New("decode aggregate evidence package")
		}
		objects = append(objects, object)
	}
	if len(objects) != len(expectedKinds) {
		return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence package object count is invalid")
	}

	configMapName, runID := "", ""
	creates := make([]SubmissionStageCreatePlan, 0, len(objects))
	for index, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		if kind != expectedKinds[index] {
			return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence package create order is invalid")
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence package object metadata is invalid")
		}
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || namespace != submissionStageInputNamespace || metadata["generateName"] != nil {
			return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence package object identity is invalid")
		}
		collectionPath, objectPath, err := submissionStageCreatePaths(apiVersion, kind, namespace, name)
		if err != nil {
			return AggregateEvidenceStageInstallationPlan{}, err
		}
		canonical, err := json.Marshal(object)
		if err != nil {
			return AggregateEvidenceStageInstallationPlan{}, errors.New("encode aggregate evidence package object")
		}
		creates = append(creates, SubmissionStageCreatePlan{
			Order: index + 1, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			PreflightMethod: "GET", ObjectPath: objectPath, CreateMethod: "POST", CollectionPath: collectionPath,
			ObjectDigest: digest.SHA256(canonical),
		})
		switch kind {
		case "ConfigMap":
			labels, _ := metadata["labels"].(map[string]any)
			if object["immutable"] != true || labels["openkubes.io/stage-id"] != receipt.StageID {
				return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence input ConfigMap semantics differ")
			}
			configMapName = name
		case "NetworkPolicy":
			runID = name
			spec, _ := object["spec"].(map[string]any)
			selector, _ := spec["podSelector"].(map[string]any)
			matchLabels, _ := selector["matchLabels"].(map[string]any)
			if matchLabels["openkubes.io/execution-id"] != runID {
				return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence NetworkPolicy selector differs from run identity")
			}
		case "Job":
			if name != runID {
				return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence Job and NetworkPolicy identities differ")
			}
			spec, _ := object["spec"].(map[string]any)
			template, _ := spec["template"].(map[string]any)
			podSpec, _ := template["spec"].(map[string]any)
			if podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" || podSpec["automountServiceAccountToken"] != false {
				return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence Job runtime identity is invalid")
			}
			if !jobMountsInputConfigMap(podSpec, configMapName) || !jobUsesManagementAuthority(podSpec, packaged.managementAuthority) || !aggregateEvidenceJobUsesAuthority(podSpec, "--gitops-authority", packaged.gitOpsAuthority) || !jobUsesAggregateEvidencePrivateObjects(podSpec, packaged) {
				return AggregateEvidenceStageInstallationPlan{}, errors.New("aggregate evidence Job binding differs from verified package")
			}
		}
	}
	return AggregateEvidenceStageInstallationPlan{
		Format: AggregateEvidenceStageInstallationPlanFormat, State: "VERIFIED", StageID: receipt.StageID,
		EvidencePackageDigest: receipt.PackageDigest, Authority: packaged.managementAuthority,
		Creates: creates, MutationAllowed: false,
	}, nil
}

func aggregateEvidenceJobUsesAuthority(podSpec map[string]any, flag, authority string) bool {
	containers, ok := podSpec["containers"].([]any)
	if !ok || len(containers) != 1 {
		return false
	}
	container, _ := containers[0].(map[string]any)
	arguments, ok := container["args"].([]any)
	if !ok {
		return false
	}
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == flag && arguments[index+1] == authority {
			return true
		}
	}
	return false
}

func jobUsesAggregateEvidencePrivateObjects(podSpec map[string]any, packaged VerifiedAggregateEvidenceStagePackage) bool {
	volumes, ok := podSpec["volumes"].([]any)
	if !ok {
		return false
	}
	want := map[string]struct {
		secret string
		items  map[string]string
	}{
		"ledger-credential":     {secret: packaged.ledgerCredential, items: map[string]string{"token": "token", "ca.crt": "ca.crt"}},
		"management-credential": {secret: packaged.managementCredential, items: map[string]string{"token": "token", "ca.crt": "ca.crt"}},
		"workload-credential":   {secret: packaged.workloadCredential, items: map[string]string{"token": "token", "ca.crt": "ca.crt"}},
		"argo-credential":       {secret: packaged.argoCredential, items: map[string]string{"token": "token", "ca.crt": "ca.crt"}},
		"runtime-binding":       {secret: packaged.runtimeSecret, items: map[string]string{"runtime-binding.json": "runtime-binding.json", "runtime-binding-receipt.json": "runtime-binding-receipt.json"}},
		"platform-capability":   {secret: packaged.capabilitySecret, items: map[string]string{"platform-capability.json": "platform-capability.json"}},
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
